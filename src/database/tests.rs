use anyhow::Result;
use rusqlite::{params, Connection};
use tempfile::tempdir;
use std::path::Path;
use chrono::Utc;

use crate::config;
use crate::database::{self, models::*};
use crate::security;

/// Test fixture for database tests
fn setup_test_db() -> (tempfile::TempDir, rusqlite::Connection) {
    // Create a temporary directory for the test database
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_db.db");
    
    // Override config for testing
    let mut config = config::get_config();
    config.database.path = db_path.to_str().unwrap().to_string();
    config.database.encrypt = true;
    config::update_config(config).unwrap();
    
    // Initialize database
    database::initialize().unwrap();
    
    // Create a direct connection to the database file for testing
    let conn = Connection::open(db_path).unwrap();
    
    (dir, conn)
}

#[test]
fn test_schema_creation() {
    let (_dir, conn) = setup_test_db();
    
    // Check if all tables exist
    let tables = vec![
        "users", "accounts", "transactions", "audit_logs", 
        "recurring_transactions", "recovery_codes", "tokens",
        "compliance_checks", "database_version"
    ];
    
    for table in tables {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [table],
            |row| row.get(0),
        ).unwrap();
        
        assert!(exists, "Table '{}' should exist", table);
    }
    
    // Check if indices exist
    let indices = vec![
        "idx_users_username", "idx_accounts_user_id", "idx_transactions_account_id",
        "idx_audit_logs_user_id", "idx_audit_logs_timestamp", "idx_audit_logs_event_type"
    ];
    
    for index in indices {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name=?)",
            [index],
            |row| row.get(0),
        ).unwrap();
        
        assert!(exists, "Index '{}' should exist", index);
    }
    
    // Check if triggers exist
    let triggers = vec![
        "account_audit_trigger", "transaction_audit_trigger", "user_audit_trigger"
    ];
    
    for trigger in triggers {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?)",
            [trigger],
            |row| row.get(0),
        ).unwrap();
        
        assert!(exists, "Trigger '{}' should exist", trigger);
    }
}

#[test]
fn test_user_crud_operations() {
    let (_dir, conn) = setup_test_db();
    
    // Create a test user
    let username = "testuser";
    let password_hash = "hashvalue";
    let salt = "saltsalt";
    let role = UserRole::User;
    
    let user = User::new(
        username.to_string(),
        password_hash.to_string(),
        salt.to_string(),
        role,
    );
    
    let user_id = user.id.clone(); // Clone the ID for later use
    
    // Insert the user
    conn.execute(
        "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
                           account_locked, created_at, updated_at, totp_enabled)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            user.id,
            user.username,
            user.password_hash,
            user.salt,
            user.role.as_str(),
            user.failed_login_attempts,
            user.account_locked as i32,
            user.created_at.to_rfc3339(),
            user.updated_at.to_rfc3339(),
            user.totp_enabled as i32,
        ],
    ).unwrap();
    
    // Read the user back
    let read_user_id: String = conn.query_row(
        "SELECT id FROM users WHERE username = ?",
        [username],
        |row| row.get(0),
    ).unwrap();
    
    assert_eq!(read_user_id, user_id, "User ID should match");
    
    // Update the user
    conn.execute(
        "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
        params![3, &user_id],
    ).unwrap();
    
    // Read the updated value
    let failed_attempts: i32 = conn.query_row(
        "SELECT failed_login_attempts FROM users WHERE id = ?",
        [&user_id],
        |row| row.get(0),
    ).unwrap();
    
    assert_eq!(failed_attempts, 3, "Failed login attempts should be updated");
    
    // Delete the user
    conn.execute(
        "DELETE FROM users WHERE id = ?",
        [&user_id],
    ).unwrap();
    
    // Verify the user is deleted
    let user_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)",
        [&user_id],
        |row| row.get(0),
    ).unwrap();
    
    assert!(!user_exists, "User should be deleted");
}

#[test]
fn test_account_and_transaction_operations() {
    let (_dir, conn) = setup_test_db();
    
    // Create a test user
    let user = User::new(
        "accountuser".to_string(),
        "hash".to_string(),
        "salt".to_string(),
        UserRole::User,
    );
    
    let user_id = user.id.clone(); // Clone for later use
    
    // Insert the user
    conn.execute(
        "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
                           account_locked, created_at, updated_at, totp_enabled)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            user.id,
            user.username,
            user.password_hash,
            user.salt,
            user.role.as_str(),
            user.failed_login_attempts,
            user.account_locked as i32,
            user.created_at.to_rfc3339(),
            user.updated_at.to_rfc3339(),
            user.totp_enabled as i32,
        ],
    ).unwrap();
    
    // Create a test account
    let account = Account::new(
        user_id,
        AccountType::Checking,
    );
    
    let account_id = account.id.clone(); // Clone for later use
    
    // Insert the account
    conn.execute(
        "INSERT INTO accounts (id, user_id, account_type, balance, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![
            account.id,
            account.user_id,
            account.account_type.as_str(),
            account.balance,
            account.status.as_str(),
            account.created_at.to_rfc3339(),
            account.updated_at.to_rfc3339(),
        ],
    ).unwrap();
    
    // Create a transaction
    let transaction = Transaction::new(
        account_id.clone(),
        TransactionType::Deposit,
        100.0,
        None,
    );
    
    // Insert the transaction
    conn.execute(
        "INSERT INTO transactions (id, account_id, transaction_type, amount, status, timestamp)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            transaction.id,
            transaction.account_id,
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.status.as_str(),
            transaction.timestamp.to_rfc3339(),
        ],
    ).unwrap();
    
    // Update account balance
    conn.execute(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        params![transaction.amount, &account_id],
    ).unwrap();
    
    // Read the updated balance
    let balance: f64 = conn.query_row(
        "SELECT balance FROM accounts WHERE id = ?",
        [&account_id],
        |row| row.get(0),
    ).unwrap();
    
    assert_eq!(balance, 100.0, "Account balance should be updated");
    
    // Check if an audit log was created (via the trigger)
    let audit_log_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM audit_logs WHERE account_id = ?)",
        [&account_id],
        |row| row.get(0),
    ).unwrap();
    
    assert!(audit_log_exists, "Audit log should be created by trigger");
}

#[test]
fn test_database_encryption() {
    // Override config for testing
    let mut config = config::get_config();
    config.database.encrypt = true;
    config::update_config(config).unwrap();
    
    // Test sensitive data
    let sensitive_data = "Credit card number: 1234-5678-9012-3456";
    
    // Encrypt the data
    let encrypted = database::encrypt_data(sensitive_data).unwrap();
    
    // Verify it's not plaintext
    assert_ne!(encrypted, sensitive_data, "Encrypted data should not match original");
    assert!(!encrypted.contains("1234-5678"), "Encrypted data should not contain original text");
    
    // Decrypt the data
    let decrypted = database::decrypt_data(&encrypted).unwrap();
    
    // Verify decryption works
    assert_eq!(decrypted, sensitive_data, "Decrypted data should match original");
}

#[test]
fn test_database_backup_restore() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("original.db").to_str().unwrap().to_string();
    let backup_path = dir.path().join("backup.db").to_str().unwrap().to_string();
    
    // Override config for testing
    let mut config = config::get_config();
    config.database.path = db_path.clone();
    config.database.encrypt = false; // Simpler test without encryption
    config::update_config(config).unwrap();
    
    // Initialize database
    database::initialize().unwrap();
    
    // Get a connection and add test data
    {
        let conn = database::get_connection().unwrap();
        
        // Create a test user
        let user = User::new(
            "backupuser".to_string(),
            "hash".to_string(),
            "salt".to_string(),
            UserRole::User,
        );
        
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
                               account_locked, created_at, updated_at, totp_enabled)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.salt,
                user.role.as_str(),
                user.failed_login_attempts,
                user.account_locked as i32,
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
                user.totp_enabled as i32,
            ],
        ).unwrap();
    }
    
    // Create a backup
    database::create_backup(&backup_path).unwrap();
    
    // Verify backup exists
    assert!(Path::new(&backup_path).exists(), "Backup file should exist");
    
    // Restore from backup
    database::restore_backup(&backup_path).unwrap();
    
    // Verify data still exists
    let conn = database::get_connection().unwrap();
    let user_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = 'backupuser')",
        [],
        |row| row.get(0),
    ).unwrap();
    
    assert!(user_exists, "User should exist after restore");
}

#[test]
fn test_connection_pool() {
    let (_dir, _) = setup_test_db();
    
    // Get multiple connections from the pool
    let connections: Vec<_> = (0..5)
        .map(|_| database::get_connection().unwrap())
        .collect();
    
    // Verify all connections are working
    for conn in &connections {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert!(count > 0, "Connection should be able to query the database");
    }
    
    // Verify connections are returned to the pool when dropped
    drop(connections);
    
    // Should be able to get more connections
    let more_connections: Vec<_> = (0..5)
        .map(|_| database::get_connection().unwrap())
        .collect();
    
    assert_eq!(more_connections.len(), 5, "Should get 5 more connections from the pool");
} 