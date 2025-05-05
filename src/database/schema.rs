use anyhow::{Result, Context};
use log::debug;
use rusqlite::Connection;
use crate::security::trusted_devices;

/// Create the database schema
pub fn create_schema(conn: &mut Connection) -> Result<()> {
    debug!("Creating database schema");
    
    // Use a transaction to ensure all tables are created or none
    let tx = conn.transaction().context("Failed to start transaction for schema creation")?;
    
    // Create users table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            account_locked INTEGER NOT NULL DEFAULT 0,
            lockout_time TEXT,
            last_login TEXT,
            password_changed TEXT,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    ).context("Failed to create users table")?;
    
    // Create accounts table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0,
            encrypted_details TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        [],
    ).context("Failed to create accounts table")?;
    
    // Create transactions table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            reference_id TEXT,
            encrypted_details TEXT,
            status TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        )",
        [],
    ).context("Failed to create transactions table")?;
    
    // Create audit_logs table - append-only design
    tx.execute(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            user_id TEXT,
            account_id TEXT,
            transaction_id TEXT,
            ip_address TEXT,
            details TEXT,
            encrypted_details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (transaction_id) REFERENCES transactions(id)
        )",
        [],
    ).context("Failed to create audit_logs table")?;
    
    // Create recurring_transactions table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS recurring_transactions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            from_account_id TEXT NOT NULL,
            to_account_id TEXT,
            external_account TEXT,
            amount REAL NOT NULL,
            frequency TEXT NOT NULL,
            next_date TEXT NOT NULL,
            end_date TEXT,
            encrypted_details TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (from_account_id) REFERENCES accounts(id),
            FOREIGN KEY (to_account_id) REFERENCES accounts(id)
        )",
        [],
    ).context("Failed to create recurring_transactions table")?;
    
    // Create recovery_codes table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        [],
    ).context("Failed to create recovery_codes table")?;
    
    // Create tokens table for JWT/JWE token tracking
    tx.execute(
        "CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            device_info TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        [],
    ).context("Failed to create tokens table")?;
    
    // Create compliance_checks table
    tx.execute(
        "CREATE TABLE IF NOT EXISTS compliance_checks (
            id TEXT PRIMARY KEY,
            check_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT,
            encrypted_details TEXT,
            run_by TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (run_by) REFERENCES users(id)
        )",
        [],
    ).context("Failed to create compliance_checks table")?;
    
    // Create indices for faster lookups
    tx.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)", [])
        .context("Failed to create index on users.username")?;
    
    tx.execute("CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)", [])
        .context("Failed to create index on accounts.user_id")?;
    
    tx.execute("CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON transactions(account_id)", [])
        .context("Failed to create index on transactions.account_id")?;
    
    tx.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)", [])
        .context("Failed to create index on audit_logs.user_id")?;
    
    tx.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)", [])
        .context("Failed to create index on audit_logs.timestamp")?;
    
    tx.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type)", [])
        .context("Failed to create index on audit_logs.event_type")?;
    
    // Commit the transaction
    tx.commit().context("Failed to commit schema creation transaction")?;
    
    // Create trusted devices schema
    trusted_devices::create_schema(conn).context("Failed to create trusted devices schema")?;
    
    debug!("Database schema created successfully");
    Ok(())
}

/// Create triggers for audit logging
pub fn create_audit_triggers(conn: &mut Connection) -> Result<()> {
    debug!("Creating audit triggers");
    
    // Create trigger for account modifications
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS account_audit_trigger
        AFTER UPDATE ON accounts
        BEGIN
            INSERT INTO audit_logs (
                id, event_type, user_id, account_id, details, timestamp
            )
            VALUES (
                lower(hex(randomblob(16))),
                'account_update',
                NULL,
                NEW.id,
                json_object(
                    'old_balance', OLD.balance,
                    'new_balance', NEW.balance,
                    'old_status', OLD.status,
                    'new_status', NEW.status
                ),
                datetime('now')
            );
        END;",
        [],
    ).context("Failed to create account_audit_trigger")?;
    
    // Create trigger for transaction insertions
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS transaction_audit_trigger
        AFTER INSERT ON transactions
        BEGIN
            INSERT INTO audit_logs (
                id, event_type, transaction_id, account_id, details, timestamp
            )
            VALUES (
                lower(hex(randomblob(16))),
                'transaction_created',
                NEW.id,
                NEW.account_id,
                json_object(
                    'transaction_type', NEW.transaction_type,
                    'amount', NEW.amount,
                    'status', NEW.status
                ),
                datetime('now')
            );
        END;",
        [],
    ).context("Failed to create transaction_audit_trigger")?;
    
    // Create trigger for user modifications
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS user_audit_trigger
        AFTER UPDATE ON users
        BEGIN
            INSERT INTO audit_logs (
                id, event_type, user_id, details, timestamp
            )
            VALUES (
                lower(hex(randomblob(16))),
                'user_update',
                NEW.id,
                json_object(
                    'old_role', OLD.role,
                    'new_role', NEW.role,
                    'old_locked', OLD.account_locked,
                    'new_locked', NEW.account_locked,
                    'old_totp_enabled', OLD.totp_enabled,
                    'new_totp_enabled', NEW.totp_enabled
                ),
                datetime('now')
            );
        END;",
        [],
    ).context("Failed to create user_audit_trigger")?;
    
    debug!("Audit triggers created successfully");
    Ok(())
} 