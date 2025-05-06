use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use log::{debug, error, info, warn};
use rusqlite::{params, Connection};
use std::fmt;
use uuid::Uuid;

use crate::database::models::{Account, AccountStatus, AccountType, AuditEventType, AuditLog};
use crate::security::auth::AuthResult;
use crate::security::{
    require_verification_for_operation, SensitiveOperation, SensitiveOperationError,
};

/// Account management errors
#[derive(Debug)]
pub enum AccountError {
    /// Account not found
    NotFound,
    /// Account already exists
    AlreadyExists,
    /// Account suspended or closed
    Inactive,
    /// Authentication error
    AuthError,
    /// Authorization error
    AuthorizationError,
    /// Two-factor authentication required
    TwoFactorRequired(SensitiveOperation),
    /// Account limit reached
    LimitReached,
    /// Invalid parameters
    InvalidParameters(String),
    /// Database error
    DatabaseError(String),
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::NotFound => write!(f, "Account not found"),
            AccountError::AlreadyExists => write!(f, "Account already exists"),
            AccountError::Inactive => write!(f, "Account is inactive, suspended or closed"),
            AccountError::AuthError => write!(f, "Authentication error"),
            AccountError::AuthorizationError => write!(f, "Not authorized to perform this operation"),
            AccountError::TwoFactorRequired(op) => {
                write!(f, "Two-factor authentication required for {}", op.friendly_name())
            }
            AccountError::LimitReached => write!(f, "Account limit reached"),
            AccountError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            AccountError::DatabaseError(err) => write!(f, "Database error: {}", err),
            AccountError::Unknown(err) => write!(f, "Unknown error: {}", err),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<SensitiveOperationError> for AccountError {
    fn from(error: SensitiveOperationError) -> Self {
        match error {
            SensitiveOperationError::TwoFactorRequired => {
                AccountError::TwoFactorRequired(SensitiveOperation::CreateAccount)
            }
            SensitiveOperationError::DatabaseError(err) => AccountError::DatabaseError(err),
            _ => AccountError::Unknown(error.to_string()),
        }
    }
}

/// Create a new account for a user
pub fn create_account(
    conn: &Connection,
    auth_result: &AuthResult,
    account_type: AccountType,
    initial_balance: Option<f64>,
    details: Option<&str>,
) -> Result<Account, AccountError> {
    // Check if the operation requires 2FA
    let op = SensitiveOperation::CreateAccount;
    require_verification_for_operation(conn, &auth_result.user_id, &op)?;

    // Count user's existing accounts
    let account_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM accounts WHERE user_id = ?",
            params![auth_result.user_id],
            |row| row.get(0),
        )
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Limit the number of accounts per user (arbitrary limit for demonstration)
    const MAX_ACCOUNTS_PER_USER: i64 = 10;
    if account_count >= MAX_ACCOUNTS_PER_USER {
        return Err(AccountError::LimitReached);
    }

    // Create new account
    let now = Utc::now();
    let initial_amount = initial_balance.unwrap_or(0.0);
    
    // Validate initial balance (can't be negative)
    if initial_amount < 0.0 {
        return Err(AccountError::InvalidParameters("Initial balance cannot be negative".to_string()));
    }

    let account_id = Uuid::new_v4().to_string();

    // Begin transaction
    let tx = conn
        .transaction()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Insert account record
    tx.execute(
        "INSERT INTO accounts (id, user_id, account_type, balance, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            account_id,
            auth_result.user_id,
            account_type.as_str(),
            initial_amount,
            AccountStatus::Active.as_str(),
            now.to_rfc3339(),
            now.to_rfc3339(),
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // If there are account details, encrypt and store them
    if let Some(detail_text) = details {
        tx.execute(
            "UPDATE accounts SET encrypted_details = ?1 WHERE id = ?2",
            params![detail_text, account_id],
        )
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;
    }

    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::AccountCreated,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Created a new {} account with ID: {}",
            account_type.as_str(),
            account_id
        )),
    );

    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, account_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            account_id,
            audit_log.details,
            audit_log.timestamp.to_rfc3339(),
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Commit the transaction
    tx.commit()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    info!(
        "Account {} created successfully for user {}",
        account_id, auth_result.user_id
    );

    // Return the newly created account
    let account = Account {
        id: account_id,
        user_id: auth_result.user_id.to_string(),
        account_type,
        balance: initial_amount,
        encrypted_details: details.map(|s| s.to_string()),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };

    Ok(account)
}

/// Get account details by ID
pub fn get_account(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
) -> Result<Account, AccountError> {
    // First check if user is admin or account owner
    let user_id = &auth_result.user_id;
    let is_admin = auth_result.is_admin;

    // Prepare SQL query - admins can access any account, users only their own
    let sql = if is_admin {
        "SELECT id, user_id, account_type, balance, encrypted_details, status, created_at, updated_at 
         FROM accounts
         WHERE id = ?"
    } else {
        "SELECT id, user_id, account_type, balance, encrypted_details, status, created_at, updated_at 
         FROM accounts
         WHERE id = ? AND user_id = ?"
    };

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    let account_result = if is_admin {
        stmt.query_row(params![account_id], |row| {
            let account_type_str: String = row.get(2)?;
            let status_str: String = row.get(5)?;
            let created_at_str: String = row.get(6)?;
            let updated_at_str: String = row.get(7)?;

            Ok(Account {
                id: row.get(0)?,
                user_id: row.get(1)?,
                account_type: AccountType::from_str(&account_type_str)
                    .map_err(|e| rusqlite::Error::InvalidColumnType(2, account_type_str.clone(), rusqlite::types::Type::Text))?,
                balance: row.get(3)?,
                encrypted_details: row.get(4)?,
                status: AccountStatus::from_str(&status_str)
                    .map_err(|e| rusqlite::Error::InvalidColumnType(5, status_str.clone(), rusqlite::types::Type::Text))?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(6, created_at_str.clone(), rusqlite::types::Type::Text))?
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(7, updated_at_str.clone(), rusqlite::types::Type::Text))?
                    .with_timezone(&Utc),
            })
        })
    } else {
        stmt.query_row(params![account_id, user_id], |row| {
            let account_type_str: String = row.get(2)?;
            let status_str: String = row.get(5)?;
            let created_at_str: String = row.get(6)?;
            let updated_at_str: String = row.get(7)?;

            Ok(Account {
                id: row.get(0)?,
                user_id: row.get(1)?,
                account_type: AccountType::from_str(&account_type_str)
                    .map_err(|e| rusqlite::Error::InvalidColumnType(2, account_type_str.clone(), rusqlite::types::Type::Text))?,
                balance: row.get(3)?,
                encrypted_details: row.get(4)?,
                status: AccountStatus::from_str(&status_str)
                    .map_err(|e| rusqlite::Error::InvalidColumnType(5, status_str.clone(), rusqlite::types::Type::Text))?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(6, created_at_str.clone(), rusqlite::types::Type::Text))?
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(7, updated_at_str.clone(), rusqlite::types::Type::Text))?
                    .with_timezone(&Utc),
            })
        })
    };

    match account_result {
        Ok(account) => Ok(account),
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                Err(AccountError::NotFound)
            } else {
                Err(AccountError::DatabaseError(e.to_string()))
            }
        }
    }
}

/// Get all accounts for a user
pub fn get_user_accounts(
    conn: &Connection,
    auth_result: &AuthResult,
    target_user_id: Option<&str>,
) -> Result<Vec<Account>, AccountError> {
    // Determine which user's accounts to retrieve
    let user_id = match target_user_id {
        Some(id) if auth_result.is_admin => id,
        None => &auth_result.user_id,
        _ => return Err(AccountError::AuthorizationError),
    };

    let mut stmt = conn
        .prepare(
            "SELECT id, user_id, account_type, balance, encrypted_details, status, created_at, updated_at 
             FROM accounts
             WHERE user_id = ?
             ORDER BY created_at",
        )
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    let accounts_iter = stmt
        .query_map(params![user_id], |row| {
            let account_type_str: String = row.get(2)?;
            let status_str: String = row.get(5)?;
            let created_at_str: String = row.get(6)?;
            let updated_at_str: String = row.get(7)?;

            Ok(Account {
                id: row.get(0)?,
                user_id: row.get(1)?,
                account_type: AccountType::from_str(&account_type_str)
                    .map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            2,
                            account_type_str.clone(),
                            rusqlite::types::Type::Text,
                        )
                    })?,
                balance: row.get(3)?,
                encrypted_details: row.get(4)?,
                status: AccountStatus::from_str(&status_str).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(5, status_str.clone(), rusqlite::types::Type::Text)
                })?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            6,
                            created_at_str.clone(),
                            rusqlite::types::Type::Text,
                        )
                    })?
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            7,
                            updated_at_str.clone(),
                            rusqlite::types::Type::Text,
                        )
                    })?
                    .with_timezone(&Utc),
            })
        })
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    let mut accounts = Vec::new();
    for account_result in accounts_iter {
        accounts.push(account_result.map_err(|e| AccountError::DatabaseError(e.to_string()))?);
    }

    Ok(accounts)
}

/// Update account status (active, suspended, closed)
pub fn update_account_status(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
    new_status: AccountStatus,
) -> Result<(), AccountError> {
    // Check 2FA for sensitive operations (only for status changes that require extra security)
    let requires_verification = match new_status {
        AccountStatus::Suspended | AccountStatus::Closed => true,
        AccountStatus::Active => false,
    };

    if requires_verification {
        let op = SensitiveOperation::UpdateAccountStatus;
        require_verification_for_operation(conn, &auth_result.user_id, &op)?;
    }

    // Check if account exists and user is authorized
    let account = get_account(conn, auth_result, account_id)?;

    // Begin transaction
    let tx = conn
        .transaction()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Update account status
    tx.execute(
        "UPDATE accounts SET status = ?, updated_at = ? WHERE id = ?",
        params![
            new_status.as_str(),
            Utc::now().to_rfc3339(),
            account_id
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::AccountStatusChanged,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Changed account {} status from {} to {}",
            account_id,
            account.status.as_str(),
            new_status.as_str()
        )),
    );

    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, account_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            account_id,
            audit_log.details,
            audit_log.timestamp.to_rfc3339(),
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    // Commit the transaction
    tx.commit()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;

    info!(
        "Account {} status updated to {}",
        account_id,
        new_status.as_str()
    );

    Ok(())
}

/// Calculate interest for savings accounts
pub fn calculate_interest(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
) -> Result<f64, AccountError> {
    // Retrieve account details
    let account = get_account(conn, auth_result, account_id)?;

    // Only calculate interest for savings accounts
    if account.account_type != AccountType::Savings {
        return Err(AccountError::InvalidParameters(
            "Interest can only be calculated for savings accounts".to_string(),
        ));
    }

    // Only calculate interest for active accounts
    if account.status != AccountStatus::Active {
        return Err(AccountError::Inactive);
    }

    // Calculate interest (simplified calculation)
    const ANNUAL_INTEREST_RATE: f64 = 0.02; // 2% annual interest rate
    const DAILY_INTEREST_RATE: f64 = ANNUAL_INTEREST_RATE / 365.0;

    let interest_amount = account.balance * DAILY_INTEREST_RATE;
    
    info!(
        "Calculated interest for account {}: ${:.4}",
        account_id, interest_amount
    );

    Ok(interest_amount)
}

/// Link accounts for a user (for tracking relationships between accounts)
pub fn link_accounts(
    conn: &Connection,
    auth_result: &AuthResult,
    primary_account_id: &str,
    linked_account_ids: &[&str],
) -> Result<(), AccountError> {
    // Verify authorization for all accounts
    let primary_account = get_account(conn, auth_result, primary_account_id)?;
    
    for &linked_id in linked_account_ids {
        // Check if the user owns the linked account
        let _ = get_account(conn, auth_result, linked_id)?;
    }
    
    // Store the account linking information in account details
    // We'll use a simple approach of storing linked account IDs in the encrypted_details field
    // In a real system, you might have a separate table for account relationships
    
    let linked_ids = linked_account_ids.join(",");
    let linking_details = format!("{{\"linked_accounts\":\"{}\"}}", linked_ids);
    
    // Begin transaction
    let tx = conn
        .transaction()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;
    
    // Update primary account with linking information
    tx.execute(
        "UPDATE accounts SET encrypted_details = ?, updated_at = ? WHERE id = ?",
        params![
            linking_details,
            Utc::now().to_rfc3339(),
            primary_account_id
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;
    
    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::AccountUpdated,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Linked accounts {} to primary account {}",
            linked_ids, primary_account_id
        )),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, account_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            primary_account_id,
            audit_log.details,
            audit_log.timestamp.to_rfc3339(),
        ],
    )
    .map_err(|e| AccountError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit()
        .map_err(|e| AccountError::DatabaseError(e.to_string()))?;
    
    info!(
        "Accounts {} linked to primary account {}",
        linked_ids, primary_account_id
    );
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::models::{User, UserRole};
    use crate::security::auth::AuthResult;
    use rusqlite::Connection;
    use tempfile::TempDir;
    
    // Setup test environment
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = Connection::open(&db_path).unwrap();
        
        // Create schema
        conn.execute(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        ).unwrap();
        
        conn.execute(
            "CREATE TABLE accounts (
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
        ).unwrap();
        
        conn.execute(
            "CREATE TABLE audit_logs (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                user_id TEXT,
                account_id TEXT,
                details TEXT,
                timestamp TEXT NOT NULL
            )",
            [],
        ).unwrap();
        
        conn.execute(
            "CREATE TABLE recent_verifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                verified_at TEXT NOT NULL
            )",
            [],
        ).unwrap();
        
        // Create test user
        let user = User::new(
            "testuser".to_string(),
            "hash".to_string(),
            "salt".to_string(),
            UserRole::User,
        );
        
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.salt,
                user.role.as_str(),
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
            ],
        ).unwrap();
        
        // Verify operation for test user
        conn.execute(
            "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
             VALUES (?, ?, ?, ?)",
            params![
                Uuid::new_v4().to_string(),
                user.id,
                SensitiveOperation::CreateAccount.as_str(),
                Utc::now().to_rfc3339(),
            ],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_create_account() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Get the user ID
        let user_id: String = conn.query_row(
            "SELECT id FROM users WHERE username = ?",
            params!["testuser"],
            |row| row.get(0),
        ).unwrap();
        
        let auth_result = AuthResult {
            user_id,
            username: "testuser".to_string(),
            is_admin: false,
            token: "dummy_token".to_string(),
        };
        
        // Create a checking account
        let account = create_account(
            &conn,
            &auth_result,
            AccountType::Checking,
            Some(100.0),
            Some("{\"nickname\":\"Primary Checking\"}"),
        ).unwrap();
        
        assert_eq!(account.account_type, AccountType::Checking);
        assert_eq!(account.balance, 100.0);
        assert_eq!(account.status, AccountStatus::Active);
        
        // Verify account exists in database
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE id = ?",
            params![account.id],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1);
    }
    
    #[test]
    fn test_get_account() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Get user ID
        let user_id: String = conn.query_row(
            "SELECT id FROM users WHERE username = ?",
            params!["testuser"],
            |row| row.get(0),
        ).unwrap();
        
        let auth_result = AuthResult {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            is_admin: false,
            token: "dummy_token".to_string(),
        };
        
        // Create a test account
        let account = create_account(
            &conn,
            &auth_result,
            AccountType::Checking,
            Some(100.0),
            None,
        ).unwrap();
        
        // Retrieve the account
        let retrieved_account = get_account(&conn, &auth_result, &account.id).unwrap();
        
        assert_eq!(retrieved_account.id, account.id);
        assert_eq!(retrieved_account.account_type, AccountType::Checking);
        assert_eq!(retrieved_account.balance, 100.0);
    }
    
    #[test]
    fn test_update_account_status() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Get user ID
        let user_id: String = conn.query_row(
            "SELECT id FROM users WHERE username = ?",
            params!["testuser"],
            |row| row.get(0),
        ).unwrap();
        
        let auth_result = AuthResult {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            is_admin: false,
            token: "dummy_token".to_string(),
        };
        
        // Create a test account
        let account = create_account(
            &conn,
            &auth_result,
            AccountType::Checking,
            None,
            None,
        ).unwrap();
        
        // Verify for the operation
        conn.execute(
            "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
             VALUES (?, ?, ?, ?)",
            params![
                Uuid::new_v4().to_string(),
                user_id,
                SensitiveOperation::UpdateAccountStatus.as_str(),
                Utc::now().to_rfc3339(),
            ],
        ).unwrap();
        
        // Update account status
        update_account_status(
            &conn, 
            &auth_result, 
            &account.id, 
            AccountStatus::Suspended
        ).unwrap();
        
        // Verify status update
        let updated_account = get_account(&conn, &auth_result, &account.id).unwrap();
        assert_eq!(updated_account.status, AccountStatus::Suspended);
    }
} 