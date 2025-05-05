use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn, error};
use rusqlite::{Connection, params};
use std::fmt;
use chrono::Utc;

use crate::database::models::{Transaction, TransactionType, TransactionStatus, AuditEventType, AuditLog};
use crate::security::auth::AuthResult;
use crate::security::{SensitiveOperation, SensitiveOperationError, require_verification_for_operation};

/// Transaction processing errors
#[derive(Debug)]
pub enum TransactionError {
    /// Insufficient funds
    InsufficientFunds,
    /// Transaction limit exceeded
    LimitExceeded,
    /// Account not found
    AccountNotFound,
    /// Account suspended or closed
    AccountInactive,
    /// Authentication error
    AuthError,
    /// Authorization error
    AuthorizationError,
    /// Two-factor authentication required
    TwoFactorRequired(SensitiveOperation),
    /// Database error
    DatabaseError(String),
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::InsufficientFunds => write!(f, "Insufficient funds for transaction"),
            TransactionError::LimitExceeded => write!(f, "Transaction limit exceeded"),
            TransactionError::AccountNotFound => write!(f, "Account not found"),
            TransactionError::AccountInactive => write!(f, "Account is inactive, suspended or closed"),
            TransactionError::AuthError => write!(f, "Authentication error"),
            TransactionError::AuthorizationError => write!(f, "Not authorized to perform this transaction"),
            TransactionError::TwoFactorRequired(op) => write!(f, "Two-factor authentication required for {}", op.friendly_name()),
            TransactionError::DatabaseError(err) => write!(f, "Database error: {}", err),
            TransactionError::Unknown(err) => write!(f, "Unknown error: {}", err),
        }
    }
}

impl std::error::Error for TransactionError {}

impl From<SensitiveOperationError> for TransactionError {
    fn from(error: SensitiveOperationError) -> Self {
        match error {
            SensitiveOperationError::TwoFactorRequired => {
                TransactionError::TwoFactorRequired(SensitiveOperation::TransferFunds)
            },
            SensitiveOperationError::DatabaseError(err) => TransactionError::DatabaseError(err),
            _ => TransactionError::Unknown(error.to_string()),
        }
    }
}

/// Process a general transaction
pub fn process_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
    transaction_type: TransactionType,
    amount: f64,
    details: Option<&str>,
) -> Result<Transaction, TransactionError> {
    // Check if account exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT balance, status FROM accounts WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![account_id, auth_result.user_id], |row| {
        let balance: f64 = row.get(0)?;
        let status: String = row.get(1)?;
        Ok((balance, status))
    });
    
    let (balance, status) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TransactionError::AccountNotFound);
            }
            return Err(TransactionError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if account is active
    if status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // For withdrawals, check if there are sufficient funds
    if transaction_type == TransactionType::Withdrawal && amount > balance {
        return Err(TransactionError::InsufficientFunds);
    }
    
    // Create transaction record
    let transaction = Transaction::new(
        account_id.to_string(),
        transaction_type,
        amount,
    );
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Insert transaction record
    tx.execute(
        "INSERT INTO transactions (id, account_id, transaction_type, amount, status, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            transaction.id,
            transaction.account_id,
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.status.as_str(),
            transaction.timestamp.to_rfc3339(),
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Update account balance
    let new_balance = match transaction.transaction_type {
        TransactionType::Deposit => balance + amount,
        TransactionType::Withdrawal => balance - amount,
        TransactionType::Transfer => balance, // Handled separately in transfer_funds
    };
    
    if transaction.transaction_type != TransactionType::Transfer {
        tx.execute(
            "UPDATE accounts SET balance = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_balance, Utc::now(), account_id],
        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    }
    
    // If there are details, encrypt and store them
    if let Some(detail_text) = details {
        // In a real implementation, this would encrypt the details
        tx.execute(
            "UPDATE transactions SET encrypted_details = ?1 WHERE id = ?2",
            params![detail_text, transaction.id],
        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    }
    
    // Create audit log
    let audit_event_type = match transaction.transaction_type {
        TransactionType::Deposit => AuditEventType::TransactionCreated,
        TransactionType::Withdrawal => AuditEventType::TransactionCreated,
        TransactionType::Transfer => AuditEventType::TransactionCreated,
    };
    
    let audit_log = AuditLog::new(
        audit_event_type,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "{} of ${:.2} to account {}",
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.account_id
        )),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp, transaction_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp,
            transaction.id
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    info!("Transaction {} processed successfully: {} ${:.2}", 
          transaction.id, transaction.transaction_type.as_str(), transaction.amount);
    
    Ok(transaction)
}

/// Transfer funds between accounts with 2FA verification requirement
pub fn transfer_funds(
    conn: &Connection,
    auth_result: &AuthResult,
    from_account_id: &str,
    to_account_id: &str,
    amount: f64,
    details: Option<&str>,
) -> Result<Transaction, TransactionError> {
    debug!("Initiating transfer of ${:.2} from account {} to account {}", 
          amount, from_account_id, to_account_id);
    
    // First, verify 2FA for sensitive transfer operation
    match require_verification_for_operation(conn, auth_result, SensitiveOperation::TransferFunds) {
        Ok(()) => {
            debug!("2FA verification confirmed for transfer operation");
        },
        Err(SensitiveOperationError::TwoFactorRequired) => {
            warn!("2FA verification required for transfer operation");
            return Err(TransactionError::TwoFactorRequired(SensitiveOperation::TransferFunds));
        },
        Err(e) => {
            error!("Error checking 2FA requirement: {}", e);
            return Err(e.into());
        }
    }
    
    // Check if both accounts exist and from_account belongs to the user
    let mut stmt = conn.prepare(
        "SELECT balance, status FROM accounts WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![from_account_id, auth_result.user_id], |row| {
        let balance: f64 = row.get(0)?;
        let status: String = row.get(1)?;
        Ok((balance, status))
    });
    
    let (from_balance, from_status) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TransactionError::AccountNotFound);
            }
            return Err(TransactionError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if from_account is active
    if from_status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // Check if there are sufficient funds
    if amount > from_balance {
        return Err(TransactionError::InsufficientFunds);
    }
    
    // Check if to_account exists
    let mut stmt = conn.prepare(
        "SELECT status FROM accounts WHERE id = ?1"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let to_status: String = match stmt.query_row(params![to_account_id], |row| {
        row.get(0)
    }) {
        Ok(status) => status,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TransactionError::AccountNotFound);
            }
            return Err(TransactionError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if to_account is active
    if to_status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // Create transaction record
    let transaction = Transaction::new(
        from_account_id.to_string(),
        TransactionType::Transfer,
        amount,
    );
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Insert transaction record
    tx.execute(
        "INSERT INTO transactions (id, account_id, transaction_type, amount, status, timestamp, to_account_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            transaction.id,
            transaction.account_id,
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.status.as_str(),
            transaction.timestamp.to_rfc3339(),
            to_account_id,
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Update from_account balance
    let new_from_balance = from_balance - amount;
    tx.execute(
        "UPDATE accounts SET balance = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_from_balance, Utc::now(), from_account_id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Update to_account balance
    tx.execute(
        "UPDATE accounts SET balance = balance + ?1, updated_at = ?2 WHERE id = ?3",
        params![amount, Utc::now(), to_account_id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // If there are details, encrypt and store them
    if let Some(detail_text) = details {
        // In a real implementation, this would encrypt the details
        tx.execute(
            "UPDATE transactions SET encrypted_details = ?1 WHERE id = ?2",
            params![detail_text, transaction.id],
        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    }
    
    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::TransactionCreated,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Transfer of ${:.2} from account {} to account {}",
            transaction.amount,
            from_account_id,
            to_account_id
        )),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp, transaction_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp,
            transaction.id
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    info!("Transfer {} processed successfully: ${:.2} from {} to {}", 
          transaction.id, transaction.amount, from_account_id, to_account_id);
    
    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::database::init_database;
    use crate::database::models::UserRole;
    use uuid::Uuid;
    
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = Connection::open(&db_path).unwrap();
        
        init_database(&conn).unwrap();
        
        // Add recent_verifications table for testing
        conn.execute(
            "CREATE TABLE IF NOT EXISTS recent_verifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )",
            [],
        ).unwrap();
        
        // Add a test user
        let user_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO users (
                id, username, password_hash, email, role, 
                account_locked, failed_login_attempts, created_at, updated_at,
                last_login, password_changed, totp_enabled
            ) VALUES (
                ?1, 'testuser', 'hash', 'test@example.com', 'regular',
                0, 0, datetime('now'), datetime('now'),
                datetime('now'), datetime('now'), 1
            )",
            params![user_id],
        ).unwrap();
        
        // Add two test accounts
        let account1_id = Uuid::new_v4().to_string();
        let account2_id = Uuid::new_v4().to_string();
        
        conn.execute(
            "INSERT INTO accounts (
                id, user_id, account_type, balance, status, created_at, updated_at
            ) VALUES (
                ?1, ?2, 'checking', 1000.0, 'active', datetime('now'), datetime('now')
            )",
            params![account1_id, user_id],
        ).unwrap();
        
        conn.execute(
            "INSERT INTO accounts (
                id, user_id, account_type, balance, status, created_at, updated_at
            ) VALUES (
                ?1, ?2, 'savings', 500.0, 'active', datetime('now'), datetime('now')
            )",
            params![account2_id, user_id],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_process_transaction() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Get user ID
        let mut stmt = conn.prepare("SELECT id FROM users WHERE username = 'testuser'").unwrap();
        let user_id: String = stmt.query_row([], |row| row.get(0)).unwrap();
        
        // Get account ID
        let mut stmt = conn.prepare("SELECT id FROM accounts WHERE user_id = ?1 AND account_type = 'checking'").unwrap();
        let account_id: String = stmt.query_row([&user_id], |row| row.get(0)).unwrap();
        
        // Create auth result for testing
        let auth_result = AuthResult {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            role: UserRole::Regular,
            tfa_verified: true,
            token_id: "test-token".to_string(),
            last_activity: Utc::now(),
        };
        
        // Process a deposit
        let transaction = process_transaction(
            &conn,
            &auth_result,
            &account_id,
            TransactionType::Deposit,
            100.0,
            Some("Test deposit"),
        ).unwrap();
        
        // Verify transaction
        assert_eq!(transaction.account_id, account_id);
        assert_eq!(transaction.transaction_type, TransactionType::Deposit);
        assert_eq!(transaction.amount, 100.0);
        assert_eq!(transaction.status, TransactionStatus::Pending);
        
        // Verify account balance was updated
        let mut stmt = conn.prepare("SELECT balance FROM accounts WHERE id = ?1").unwrap();
        let new_balance: f64 = stmt.query_row([&account_id], |row| row.get(0)).unwrap();
        assert_eq!(new_balance, 1100.0);
    }
    
    #[test]
    fn test_transfer_funds_requires_2fa() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Get user ID
        let mut stmt = conn.prepare("SELECT id FROM users WHERE username = 'testuser'").unwrap();
        let user_id: String = stmt.query_row([], |row| row.get(0)).unwrap();
        
        // Get account IDs
        let mut stmt = conn.prepare("SELECT id FROM accounts WHERE user_id = ?1 AND account_type = 'checking'").unwrap();
        let from_account_id: String = stmt.query_row([&user_id], |row| row.get(0)).unwrap();
        
        let mut stmt = conn.prepare("SELECT id FROM accounts WHERE user_id = ?1 AND account_type = 'savings'").unwrap();
        let to_account_id: String = stmt.query_row([&user_id], |row| row.get(0)).unwrap();
        
        // Create auth result for testing
        let auth_result = AuthResult {
            user_id: user_id.clone(),
            username: "testuser".to_string(),
            role: UserRole::Regular,
            tfa_verified: true,
            token_id: "test-token".to_string(),
            last_activity: Utc::now(),
        };
        
        // Try to transfer funds without 2FA verification
        let result = transfer_funds(
            &conn,
            &auth_result,
            &from_account_id,
            &to_account_id,
            100.0,
            Some("Test transfer"),
        );
        
        // Should require 2FA
        assert!(matches!(result, Err(TransactionError::TwoFactorRequired(_))));
        
        // Add a recent verification
        let now = Utc::now();
        conn.execute(
            "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
             VALUES ('test-verif-id', ?1, ?2, ?3)",
            params![user_id, SensitiveOperation::TransferFunds.as_str(), now],
        ).unwrap();
        
        // Now transfer should succeed
        let transaction = transfer_funds(
            &conn,
            &auth_result,
            &from_account_id,
            &to_account_id,
            100.0,
            Some("Test transfer"),
        ).unwrap();
        
        // Verify transaction
        assert_eq!(transaction.account_id, from_account_id);
        assert_eq!(transaction.transaction_type, TransactionType::Transfer);
        assert_eq!(transaction.amount, 100.0);
        
        // Verify account balances were updated
        let mut stmt = conn.prepare("SELECT balance FROM accounts WHERE id = ?1").unwrap();
        let new_from_balance: f64 = stmt.query_row([&from_account_id], |row| row.get(0)).unwrap();
        assert_eq!(new_from_balance, 900.0);
        
        let mut stmt = conn.prepare("SELECT balance FROM accounts WHERE id = ?1").unwrap();
        let new_to_balance: f64 = stmt.query_row([&to_account_id], |row| row.get(0)).unwrap();
        assert_eq!(new_to_balance, 600.0);
    }
} 