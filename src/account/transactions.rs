use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn, error};
use rusqlite::{Connection, params};
use std::fmt;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

use crate::database::models::{Transaction, TransactionType, TransactionStatus, AuditEventType, AuditLog};
use crate::security::auth::AuthResult;
use crate::security::{SensitiveOperation, SensitiveOperationError, require_verification_for_operation};
use crate::security::encryption;
use crate::config;

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
    /// Invalid amount (negative or zero)
    InvalidAmount,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Database error
    DatabaseError(String),
    /// Encryption error
    EncryptionError(String),
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
            TransactionError::InvalidAmount => write!(f, "Invalid transaction amount"),
            TransactionError::RateLimitExceeded => write!(f, "Transaction rate limit exceeded"),
            TransactionError::DatabaseError(err) => write!(f, "Database error: {}", err),
            TransactionError::EncryptionError(err) => write!(f, "Encryption error: {}", err),
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

/// Frequency for recurring transactions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecurrenceFrequency {
    Daily,
    Weekly,
    BiWeekly,
    Monthly,
    Quarterly,
    Yearly,
}

impl RecurrenceFrequency {
    pub fn as_str(&self) -> &str {
        match self {
            RecurrenceFrequency::Daily => "daily",
            RecurrenceFrequency::Weekly => "weekly",
            RecurrenceFrequency::BiWeekly => "biweekly",
            RecurrenceFrequency::Monthly => "monthly",
            RecurrenceFrequency::Quarterly => "quarterly",
            RecurrenceFrequency::Yearly => "yearly",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "daily" => Ok(RecurrenceFrequency::Daily),
            "weekly" => Ok(RecurrenceFrequency::Weekly),
            "biweekly" => Ok(RecurrenceFrequency::BiWeekly),
            "monthly" => Ok(RecurrenceFrequency::Monthly),
            "quarterly" => Ok(RecurrenceFrequency::Quarterly),
            "yearly" => Ok(RecurrenceFrequency::Yearly),
            _ => Err(format!("Invalid recurrence frequency: {}", s)),
        }
    }
    
    pub fn get_next_date(&self, from_date: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            RecurrenceFrequency::Daily => from_date + Duration::days(1),
            RecurrenceFrequency::Weekly => from_date + Duration::weeks(1),
            RecurrenceFrequency::BiWeekly => from_date + Duration::weeks(2),
            RecurrenceFrequency::Monthly => {
                // Simple approximation for month - in a real app would need better handling
                from_date + Duration::days(30)
            },
            RecurrenceFrequency::Quarterly => {
                // Approximation for quarter
                from_date + Duration::days(91)
            },
            RecurrenceFrequency::Yearly => {
                // Approximation for year 
                from_date + Duration::days(365)
            },
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
    debug!("Processing {} transaction for ${:.2} on account {}", 
          transaction_type.as_str(), amount, account_id);
    
    // Validate amount
    if amount <= 0.0 {
        return Err(TransactionError::InvalidAmount);
    }
    
    // Apply transaction rate limiting
    if let Err(e) = check_transaction_rate_limit(conn, auth_result.user_id.as_str()) {
        return Err(e);
    }
    
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
    
    // Create transaction record with reference ID for receipts
    let reference_id = generate_transaction_reference();
    let transaction = Transaction::new(
        account_id.to_string(),
        transaction_type.clone(),
        amount,
        Some(reference_id),
    );
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Insert transaction record
    tx.execute(
        "INSERT INTO transactions (id, account_id, transaction_type, amount, status, reference_id, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            transaction.id,
            transaction.account_id,
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.status.as_str(),
            transaction.reference_id,
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
        // Encrypt the transaction details using the current encryption key
        match encrypt_transaction_details(detail_text) {
            Ok(encrypted_details) => {
                tx.execute(
                    "UPDATE transactions SET encrypted_details = ?1 WHERE id = ?2",
                    params![encrypted_details, transaction.id],
                ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            },
            Err(e) => {
                warn!("Failed to encrypt transaction details: {}", e);
                // Still proceed with the transaction, but log the error
            }
        }
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
            "{} of ${:.2} to account {} (Ref: {})",
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.account_id,
            transaction.reference_id.as_ref().unwrap_or(&String::from("N/A"))
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
    
    // Update the transaction status to completed
    tx.execute(
        "UPDATE transactions SET status = ?1 WHERE id = ?2",
        params![TransactionStatus::Completed.as_str(), transaction.id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Generate a receipt
    let _receipt = generate_transaction_receipt(&transaction)?;
    
    info!("Transaction {} (Ref: {}) processed successfully: {} ${:.2}", 
          transaction.id, 
          transaction.reference_id.as_ref().unwrap_or(&String::from("N/A")),
          transaction.transaction_type.as_str(), 
          transaction.amount);
    
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
    
    // Validate amount
    if amount <= 0.0 {
        return Err(TransactionError::InvalidAmount);
    }
    
    // Apply transaction rate limiting
    if let Err(e) = check_transaction_rate_limit(conn, auth_result.user_id.as_str()) {
        return Err(e);
    }
    
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
    
    let to_status = stmt.query_row(params![to_account_id], |row| {
        let status: String = row.get(0)?;
        Ok(status)
    }).map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            TransactionError::AccountNotFound
        } else {
            TransactionError::DatabaseError(e.to_string())
        }
    })?;
    
    // Check if to_account is active
    if to_status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // Generate reference ID for the transaction
    let reference_id = generate_transaction_reference();
    
    // Create transaction record
    let transaction = Transaction::new(
        from_account_id.to_string(),
        TransactionType::Transfer,
        amount,
        Some(reference_id.clone()),
    );
    
    // Begin database transaction
    let tx = conn.transaction()
        .map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Insert transaction record
    tx.execute(
        "INSERT INTO transactions (id, account_id, transaction_type, amount, status, reference_id, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            transaction.id,
            transaction.account_id,
            transaction.transaction_type.as_str(),
            transaction.amount,
            transaction.status.as_str(),
            transaction.reference_id,
            transaction.timestamp.to_rfc3339(),
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Update balances
    let new_from_balance = from_balance - amount;
    
    tx.execute(
        "UPDATE accounts SET balance = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_from_balance, Utc::now(), from_account_id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    tx.execute(
        "UPDATE accounts SET balance = balance + ?1, updated_at = ?2 WHERE id = ?3",
        params![amount, Utc::now(), to_account_id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // If there are details, encrypt and store them
    if let Some(detail_text) = details {
        // Add recipient account info to details
        let enhanced_details = format!("Transfer to account {}. {}", 
                                      to_account_id, 
                                      detail_text.unwrap_or_default());
        
        // Encrypt the transaction details
        match encrypt_transaction_details(&enhanced_details) {
            Ok(encrypted_details) => {
                tx.execute(
                    "UPDATE transactions SET encrypted_details = ?1, to_account_id = ?2 WHERE id = ?3",
                    params![encrypted_details, to_account_id, transaction.id],
                ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            },
            Err(e) => {
                warn!("Failed to encrypt transaction details: {}", e);
            }
        }
    } else {
        // Still record the destination account
        tx.execute(
            "UPDATE transactions SET to_account_id = ?1 WHERE id = ?2",
            params![to_account_id, transaction.id],
        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    }
    
    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::TransactionCreated,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Transfer of ${:.2} from account {} to account {} (Ref: {})",
            amount, from_account_id, to_account_id, reference_id
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
    
    // Update transaction status to completed
    tx.execute(
        "UPDATE transactions SET status = ?1 WHERE id = ?2",
        params![TransactionStatus::Completed.as_str(), transaction.id],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Generate a receipt
    let _receipt = generate_transaction_receipt(&transaction)?;
    
    info!("Transfer {} (Ref: {}) of ${:.2} from {} to {} completed successfully", 
          transaction.id, reference_id, amount, from_account_id, to_account_id);
    
    Ok(transaction)
}

/// Generate a unique transaction reference ID
fn generate_transaction_reference() -> String {
    let timestamp = Utc::now().timestamp_millis();
    let random_part = encryption::generate_secure_token(8);
    format!("TXN-{}-{}", timestamp, random_part)
}

/// Check if user has exceeded transaction rate limits
fn check_transaction_rate_limit(conn: &Connection, user_id: &str) -> Result<(), TransactionError> {
    // Get the rate limit config - defaults if not found
    let rate_limit_count = config::get_int("security.transaction_rate_limit.count").unwrap_or(10);
    let rate_limit_window = config::get_int("security.transaction_rate_limit.window_seconds").unwrap_or(60);
    
    // Get current time minus the window
    let now = Utc::now();
    let window_start = now - chrono::Duration::seconds(rate_limit_window);
    
    // Count transactions in the rate limit window
    let count = conn.query_row(
        "SELECT COUNT(*) FROM transactions t 
         JOIN accounts a ON t.account_id = a.id 
         WHERE a.user_id = ?1 AND t.timestamp > ?2",
        params![user_id, window_start.to_rfc3339()],
        |row| row.get::<_, i64>(0),
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    if count >= rate_limit_count {
        warn!("Transaction rate limit exceeded for user {}: {} transactions in {} seconds", 
              user_id, count, rate_limit_window);
        return Err(TransactionError::RateLimitExceeded);
    }
    
    Ok(())
}

/// Encrypt transaction details
fn encrypt_transaction_details(details: &str) -> Result<String, TransactionError> {
    encryption::encrypt_string(details)
        .map_err(|e| TransactionError::EncryptionError(e.to_string()))
}

/// Decrypt transaction details
pub fn decrypt_transaction_details(encrypted_details: &str) -> Result<String, TransactionError> {
    encryption::decrypt_string(encrypted_details)
        .map_err(|e| TransactionError::EncryptionError(e.to_string()))
}

/// Generate a transaction receipt
fn generate_transaction_receipt(transaction: &Transaction) -> Result<String, TransactionError> {
    let receipt_id = Uuid::new_v4().to_string();
    let timestamp = transaction.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let transaction_type = transaction.transaction_type.as_str().to_uppercase();
    let reference = transaction.reference_id.as_ref().unwrap_or(&String::from("N/A"));
    
    let receipt = format!(
        "TRANSACTION RECEIPT\n\
        ====================\n\
        Receipt ID: {}\n\
        Transaction ID: {}\n\
        Reference: {}\n\
        Type: {}\n\
        Amount: ${:.2}\n\
        Account: {}\n\
        Date/Time: {}\n\
        Status: {}\n\
        ====================\n\
        This is an official record of your transaction.",
        receipt_id,
        transaction.id,
        reference,
        transaction_type,
        transaction.amount,
        transaction.account_id,
        timestamp,
        transaction.status.as_str().to_uppercase()
    );
    
    // In a real system, we might store this receipt or send it to the user
    debug!("Generated receipt for transaction {}", transaction.id);
    
    Ok(receipt)
}

/// Schedule a one-time future transaction
pub fn schedule_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
    transaction_type: TransactionType,
    amount: f64,
    scheduled_date: DateTime<Utc>,
    details: Option<&str>,
    to_account_id: Option<&str>,
) -> Result<String, TransactionError> {
    // Validate amount
    if amount <= 0.0 {
        return Err(TransactionError::InvalidAmount);
    }
    
    // Check if account exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT status FROM accounts WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let status = stmt.query_row(params![account_id, auth_result.user_id], |row| {
        let status: String = row.get(0)?;
        Ok(status)
    }).map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            TransactionError::AccountNotFound
        } else {
            TransactionError::DatabaseError(e.to_string())
        }
    })?;
    
    // Check if account is active
    if status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // If it's a transfer, check the destination account too
    if transaction_type == TransactionType::Transfer {
        if let Some(to_id) = to_account_id {
            let mut stmt = conn.prepare(
                "SELECT status FROM accounts WHERE id = ?1"
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            let to_status = stmt.query_row(params![to_id], |row| {
                let status: String = row.get(0)?;
                Ok(status)
            }).map_err(|e| {
                if let rusqlite::Error::QueryReturnedNoRows = e {
                    TransactionError::AccountNotFound
                } else {
                    TransactionError::DatabaseError(e.to_string())
                }
            })?;
            
            if to_status != "active" {
                return Err(TransactionError::AccountInactive);
            }
        } else {
            return Err(TransactionError::AccountNotFound);
        }
    }
    
    // Generate a unique ID for the scheduled transaction
    let scheduled_id = Uuid::new_v4().to_string();
    let reference_id = generate_transaction_reference();
    
    // Encrypt details if provided
    let encrypted_details = if let Some(detail_text) = details {
        match encrypt_transaction_details(detail_text) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                warn!("Failed to encrypt scheduled transaction details: {}", e);
                None
            }
        }
    } else {
        None
    };
    
    // Store the scheduled transaction
    conn.execute(
        "INSERT INTO scheduled_transactions 
        (id, user_id, account_id, to_account_id, transaction_type, amount, 
         scheduled_date, reference_id, encrypted_details, created_at) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            scheduled_id,
            auth_result.user_id,
            account_id,
            to_account_id,
            transaction_type.as_str(),
            amount,
            scheduled_date.to_rfc3339(),
            reference_id,
            encrypted_details,
            Utc::now().to_rfc3339(),
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::TransactionScheduled,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Scheduled {} of ${:.2} for account {} on {}",
            transaction_type.as_str(),
            amount,
            account_id,
            scheduled_date.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        )),
    );
    
    conn.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp,
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    info!("Transaction scheduled successfully: {} of ${:.2} on {}", 
          transaction_type.as_str(), amount, 
          scheduled_date.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    
    Ok(scheduled_id)
}

/// Create a recurring transaction
pub fn create_recurring_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
    transaction_type: TransactionType,
    amount: f64,
    frequency: RecurrenceFrequency,
    start_date: DateTime<Utc>,
    end_date: Option<DateTime<Utc>>,
    details: Option<&str>,
    to_account_id: Option<&str>,
) -> Result<String, TransactionError> {
    // Similar validations as schedule_transaction
    if amount <= 0.0 {
        return Err(TransactionError::InvalidAmount);
    }
    
    // Check if account exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT status FROM accounts WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let status = stmt.query_row(params![account_id, auth_result.user_id], |row| {
        let status: String = row.get(0)?;
        Ok(status)
    }).map_err(|e| {
        if let rusqlite::Error::QueryReturnedNoRows = e {
            TransactionError::AccountNotFound
        } else {
            TransactionError::DatabaseError(e.to_string())
        }
    })?;
    
    if status != "active" {
        return Err(TransactionError::AccountInactive);
    }
    
    // For transfers, check destination account
    if transaction_type == TransactionType::Transfer {
        if let Some(to_id) = to_account_id {
            let mut stmt = conn.prepare(
                "SELECT status FROM accounts WHERE id = ?1"
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            let to_status = stmt.query_row(params![to_id], |row| {
                let status: String = row.get(0)?;
                Ok(status)
            }).map_err(|e| {
                if let rusqlite::Error::QueryReturnedNoRows = e {
                    TransactionError::AccountNotFound
                } else {
                    TransactionError::DatabaseError(e.to_string())
                }
            })?;
            
            if to_status != "active" {
                return Err(TransactionError::AccountInactive);
            }
        } else {
            return Err(TransactionError::AccountNotFound);
        }
    }
    
    // Generate IDs
    let recurring_id = Uuid::new_v4().to_string();
    let reference_base = generate_transaction_reference();
    
    // Encrypt details if provided
    let encrypted_details = if let Some(detail_text) = details {
        match encrypt_transaction_details(detail_text) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                warn!("Failed to encrypt recurring transaction details: {}", e);
                None
            }
        }
    } else {
        None
    };
    
    // Store the recurring transaction definition
    conn.execute(
        "INSERT INTO recurring_transactions 
        (id, user_id, account_id, to_account_id, transaction_type, amount, frequency,
         start_date, end_date, next_date, reference_base, encrypted_details, created_at) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            recurring_id,
            auth_result.user_id,
            account_id,
            to_account_id,
            transaction_type.as_str(),
            amount,
            frequency.as_str(),
            start_date.to_rfc3339(),
            end_date.map(|d| d.to_rfc3339()),
            start_date.to_rfc3339(),  // Next date is initially the start date
            reference_base,
            encrypted_details,
            Utc::now().to_rfc3339(),
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    // Create audit log
    let audit_log = AuditLog::new(
        AuditEventType::RecurringTransactionCreated,
        Some(auth_result.user_id.to_string()),
        Some(format!(
            "Created {} recurring {} of ${:.2} for account {}, frequency: {}",
            frequency.as_str(),
            transaction_type.as_str(),
            amount,
            account_id,
            frequency.as_str()
        )),
    );
    
    conn.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp,
        ],
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    info!("Recurring transaction created: {} {} of ${:.2}, starting {}", 
          frequency.as_str(), transaction_type.as_str(), amount, 
          start_date.format("%Y-%m-%d").to_string());
    
    Ok(recurring_id)
}

/// Process all due scheduled and recurring transactions
/// This would typically be called by a background job
pub fn process_scheduled_transactions(conn: &Connection) -> Result<usize, TransactionError> {
    let now = Utc::now();
    let mut processed_count = 0;
    
    // First, process one-time scheduled transactions
    let mut stmt = conn.prepare(
        "SELECT id, user_id, account_id, to_account_id, transaction_type, amount, 
         scheduled_date, reference_id, encrypted_details
         FROM scheduled_transactions 
         WHERE scheduled_date <= ?1 AND processed = 0"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let scheduled_rows = stmt.query_map(params![now.to_rfc3339()], |row| {
        Ok((
            row.get::<_, String>(0)?, // id
            row.get::<_, String>(1)?, // user_id
            row.get::<_, String>(2)?, // account_id
            row.get::<_, Option<String>>(3)?, // to_account_id
            row.get::<_, String>(4)?, // transaction_type
            row.get::<_, f64>(5)?, // amount
            row.get::<_, String>(6)?, // scheduled_date
            row.get::<_, String>(7)?, // reference_id
            row.get::<_, Option<String>>(8)?, // encrypted_details
        ))
    }).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    for row_result in scheduled_rows {
        match row_result {
            Ok((id, user_id, account_id, to_account_id, tx_type_str, amount, 
                scheduled_date_str, reference_id, encrypted_details)) => {
                
                // Parse the transaction type
                let transaction_type = match TransactionType::from_str(&tx_type_str) {
                    Ok(tt) => tt,
                    Err(e) => {
                        warn!("Invalid transaction type in scheduled transaction {}: {}", id, e);
                        continue;
                    }
                };
                
                // Create a transaction using a system auth context
                let system_auth = AuthResult {
                    user_id: user_id.clone(),
                    username: "SYSTEM".to_string(),
                    role: "system".to_string(),
                    permissions: vec!["*".to_string()], // Full system permissions
                    token: None,
                };
                
                let tx_result = match transaction_type {
                    TransactionType::Transfer => {
                        if let Some(to_id) = to_account_id {
                            // Decrypt details if encrypted
                            let details = encrypted_details.as_ref()
                                .and_then(|enc| decrypt_transaction_details(enc).ok());
                            
                            transfer_funds(
                                conn, 
                                &system_auth,
                                &account_id,
                                &to_id,
                                amount,
                                details.as_deref(),
                            )
                        } else {
                            warn!("Scheduled transfer missing destination account: {}", id);
                            continue;
                        }
                    },
                    _ => {
                        // Decrypt details if encrypted
                        let details = encrypted_details.as_ref()
                            .and_then(|enc| decrypt_transaction_details(enc).ok());
                        
                        process_transaction(
                            conn,
                            &system_auth,
                            &account_id,
                            transaction_type,
                            amount,
                            details.as_deref(),
                        )
                    }
                };
                
                match tx_result {
                    Ok(transaction) => {
                        // Mark the scheduled transaction as processed
                        conn.execute(
                            "UPDATE scheduled_transactions SET processed = 1, processed_at = ?1, 
                             transaction_id = ?2 WHERE id = ?3",
                            params![now.to_rfc3339(), transaction.id, id],
                        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
                        
                        processed_count += 1;
                        info!("Processed scheduled transaction {}: {} {:.2}", 
                              id, transaction_type.as_str(), amount);
                    },
                    Err(e) => {
                        // Log the failure but continue processing others
                        error!("Failed to process scheduled transaction {}: {}", id, e);
                        
                        // Update the scheduled transaction with failure info
                        conn.execute(
                            "UPDATE scheduled_transactions SET failure_count = failure_count + 1, 
                             last_failure = ?1, last_error = ?2 WHERE id = ?3",
                            params![now.to_rfc3339(), e.to_string(), id],
                        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
                    }
                }
            },
            Err(e) => {
                error!("Error retrieving scheduled transaction: {}", e);
            }
        }
    }
    
    // Next, process recurring transactions that are due
    let mut stmt = conn.prepare(
        "SELECT id, user_id, account_id, to_account_id, transaction_type, amount, 
         frequency, next_date, end_date, reference_base, encrypted_details
         FROM recurring_transactions 
         WHERE next_date <= ?1 AND (end_date IS NULL OR end_date >= ?1)"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let recurring_rows = stmt.query_map(params![now.to_rfc3339()], |row| {
        Ok((
            row.get::<_, String>(0)?, // id
            row.get::<_, String>(1)?, // user_id
            row.get::<_, String>(2)?, // account_id
            row.get::<_, Option<String>>(3)?, // to_account_id
            row.get::<_, String>(4)?, // transaction_type
            row.get::<_, f64>(5)?, // amount
            row.get::<_, String>(6)?, // frequency
            row.get::<_, String>(7)?, // next_date
            row.get::<_, Option<String>>(8)?, // end_date
            row.get::<_, String>(9)?, // reference_base
            row.get::<_, Option<String>>(10)?, // encrypted_details
        ))
    }).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    for row_result in recurring_rows {
        match row_result {
            Ok((id, user_id, account_id, to_account_id, tx_type_str, amount, 
                freq_str, next_date_str, end_date_str, reference_base, encrypted_details)) => {
                
                // Parse the transaction type and frequency
                let transaction_type = match TransactionType::from_str(&tx_type_str) {
                    Ok(tt) => tt,
                    Err(e) => {
                        warn!("Invalid transaction type in recurring transaction {}: {}", id, e);
                        continue;
                    }
                };
                
                let frequency = match RecurrenceFrequency::from_str(&freq_str) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Invalid frequency in recurring transaction {}: {}", id, e);
                        continue;
                    }
                };
                
                // Parse dates
                let next_date = match DateTime::parse_from_rfc3339(&next_date_str) {
                    Ok(dt) => dt.with_timezone(&Utc),
                    Err(e) => {
                        warn!("Invalid next_date in recurring transaction {}: {}", id, e);
                        continue;
                    }
                };
                
                // Create a system auth context like before
                let system_auth = AuthResult {
                    user_id: user_id.clone(),
                    username: "SYSTEM".to_string(),
                    role: "system".to_string(),
                    permissions: vec!["*".to_string()],
                    token: None,
                };
                
                // Process the transaction
                let tx_result = match transaction_type {
                    TransactionType::Transfer => {
                        if let Some(to_id) = to_account_id.clone() {
                            // Decrypt details if encrypted
                            let details = encrypted_details.as_ref()
                                .and_then(|enc| decrypt_transaction_details(enc).ok());
                            
                            transfer_funds(
                                conn, 
                                &system_auth,
                                &account_id,
                                &to_id,
                                amount,
                                details.as_deref(),
                            )
                        } else {
                            warn!("Recurring transfer missing destination account: {}", id);
                            continue;
                        }
                    },
                    _ => {
                        // Decrypt details if encrypted
                        let details = encrypted_details.as_ref()
                            .and_then(|enc| decrypt_transaction_details(enc).ok());
                        
                        process_transaction(
                            conn,
                            &system_auth,
                            &account_id,
                            transaction_type,
                            amount,
                            details.as_deref(),
                        )
                    }
                };
                
                match tx_result {
                    Ok(transaction) => {
                        // Calculate the next occurrence
                        let next_occurrence = frequency.get_next_date(next_date);
                        
                        // Check if we've reached the end date
                        let should_continue = if let Some(end_date_str) = end_date_str {
                            match DateTime::parse_from_rfc3339(&end_date_str) {
                                Ok(end_date) => {
                                    let end_date_utc = end_date.with_timezone(&Utc);
                                    next_occurrence <= end_date_utc
                                },
                                Err(_) => true // If we can't parse end date, continue anyway
                            }
                        } else {
                            true // No end date, so continue
                        };
                        
                        if should_continue {
                            // Update the next date
                            conn.execute(
                                "UPDATE recurring_transactions SET next_date = ?1, 
                                 last_processed_at = ?2, last_transaction_id = ?3 WHERE id = ?4",
                                params![
                                    next_occurrence.to_rfc3339(), 
                                    now.to_rfc3339(), 
                                    transaction.id, 
                                    id
                                ],
                            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
                        } else {
                            // End date reached, mark as completed
                            conn.execute(
                                "UPDATE recurring_transactions SET completed = 1, 
                                 completed_at = ?1, last_transaction_id = ?2 WHERE id = ?3",
                                params![now.to_rfc3339(), transaction.id, id],
                            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
                        }
                        
                        processed_count += 1;
                        info!("Processed recurring transaction {}: {} ${:.2}", 
                              id, transaction_type.as_str(), amount);
                    },
                    Err(e) => {
                        // Log the failure but continue processing others
                        error!("Failed to process recurring transaction {}: {}", id, e);
                        
                        // Update with failure info
                        conn.execute(
                            "UPDATE recurring_transactions SET failure_count = failure_count + 1, 
                             last_failure = ?1, last_error = ?2 WHERE id = ?3",
                            params![now.to_rfc3339(), e.to_string(), id],
                        ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
                    }
                }
            },
            Err(e) => {
                error!("Error retrieving recurring transaction: {}", e);
            }
        }
    }
    
    info!("Processed {} scheduled/recurring transactions", processed_count);
    Ok(processed_count)
}

/// Get transaction history for an account
pub fn get_transaction_history(
    conn: &Connection,
    auth_result: &AuthResult,
    account_id: &str,
    limit: usize,
    offset: usize,
    start_date: Option<DateTime<Utc>>,
    end_date: Option<DateTime<Utc>>,
) -> Result<Vec<Transaction>, TransactionError> {
    // Check if account exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM accounts WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let account_count: i64 = stmt.query_row(params![account_id, auth_result.user_id], |row| {
        row.get(0)
    }).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    if account_count == 0 {
        return Err(TransactionError::AccountNotFound);
    }
    
    // Build the query with optional date filters
    let mut query = String::from(
        "SELECT id, account_id, transaction_type, amount, reference_id, 
        encrypted_details, status, timestamp, to_account_id
        FROM transactions 
        WHERE account_id = ?1"
    );
    
    let mut query_params: Vec<&dyn rusqlite::ToSql> = vec![&account_id];
    
    if let Some(start) = &start_date {
        query.push_str(" AND timestamp >= ?");
        query_params.push(&start.to_rfc3339());
    }
    
    if let Some(end) = &end_date {
        query.push_str(" AND timestamp <= ?");
        query_params.push(&end.to_rfc3339());
    }
    
    // Add ordering, limit and offset
    query.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    query_params.push(&(limit as i64));
    query_params.push(&(offset as i64));
    
    // Execute the query
    let mut stmt = conn.prepare(&query)
        .map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let transaction_rows = stmt.query_map(rusqlite::params_from_iter(query_params), |row| {
        let id: String = row.get(0)?;
        let account_id: String = row.get(1)?;
        let tx_type_str: String = row.get(2)?;
        let amount: f64 = row.get(3)?;
        let reference_id: Option<String> = row.get(4)?;
        let encrypted_details: Option<String> = row.get(5)?;
        let status_str: String = row.get(6)?;
        let timestamp_str: String = row.get(7)?;
        let to_account_id: Option<String> = row.get(8)?;
        
        // Parse transaction type
        let transaction_type = TransactionType::from_str(&tx_type_str)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e))?;
        
        // Parse status
        let status = TransactionStatus::from_str(&status_str)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e))?;
        
        // Parse timestamp
        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map_err(|_| rusqlite::Error::InvalidParameterName("Invalid timestamp".to_string()))?
            .with_timezone(&Utc);
        
        // Create a transaction object
        let mut transaction = Transaction {
            id,
            account_id,
            transaction_type,
            amount,
            reference_id,
            encrypted_details,
            status,
            timestamp,
        };
        
        Ok(transaction)
    }).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let mut transactions = Vec::new();
    for tx_result in transaction_rows {
        match tx_result {
            Ok(transaction) => {
                transactions.push(transaction);
            },
            Err(e) => {
                warn!("Error retrieving transaction: {}", e);
            }
        }
    }
    
    Ok(transactions)
}

/// Generate a transaction receipt for a completed transaction
pub fn generate_receipt_for_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    transaction_id: &str,
) -> Result<String, TransactionError> {
    // Retrieve the transaction first
    let mut stmt = conn.prepare(
        "SELECT t.id, t.account_id, t.transaction_type, t.amount, t.reference_id, 
         t.status, t.timestamp, t.to_account_id, a.user_id
         FROM transactions t
         JOIN accounts a ON t.account_id = a.id
         WHERE t.id = ?1"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let transaction_result = stmt.query_row(params![transaction_id], |row| {
        let id: String = row.get(0)?;
        let account_id: String = row.get(1)?;
        let tx_type_str: String = row.get(2)?;
        let amount: f64 = row.get(3)?;
        let reference_id: Option<String> = row.get(4)?;
        let status_str: String = row.get(5)?;
        let timestamp_str: String = row.get(6)?;
        let to_account_id: Option<String> = row.get(7)?;
        let user_id: String = row.get(8)?;
        
        Ok((id, account_id, tx_type_str, amount, reference_id, status_str, 
            timestamp_str, to_account_id, user_id))
    });
    
    match transaction_result {
        Ok((id, account_id, tx_type_str, amount, reference_id, status_str, 
            timestamp_str, to_account_id, user_id)) => {
            
            // Verify authorization - user must own the account
            if auth_result.user_id != user_id && auth_result.role != "admin" && auth_result.role != "system" {
                return Err(TransactionError::AuthorizationError);
            }
            
            // Parse transaction type and status
            let transaction_type = TransactionType::from_str(&tx_type_str)
                .map_err(|e| TransactionError::Unknown(e))?;
            
            let status = TransactionStatus::from_str(&status_str)
                .map_err(|e| TransactionError::Unknown(e))?;
            
            // Parse timestamp
            let timestamp = match DateTime::parse_from_rfc3339(&timestamp_str) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(e) => return Err(TransactionError::Unknown(e.to_string())),
            };
            
            // Create a transaction object
            let transaction = Transaction {
                id,
                account_id,
                transaction_type,
                amount,
                reference_id,
                encrypted_details: None, // Not needed for receipt
                status,
                timestamp,
            };
            
            // Generate the receipt
            let receipt_id = Uuid::new_v4().to_string();
            let formatted_timestamp = transaction.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            let transaction_type_str = transaction.transaction_type.as_str().to_uppercase();
            let reference = transaction.reference_id.as_ref().unwrap_or(&String::from("N/A"));
            
            // Extra details for transfers
            let transfer_details = if transaction.transaction_type == TransactionType::Transfer {
                if let Some(to_id) = to_account_id {
                    format!("\nDestination Account: {}", to_id)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            
            let receipt = format!(
                "TRANSACTION RECEIPT\n\
                ====================\n\
                Receipt ID: {}\n\
                Transaction ID: {}\n\
                Reference: {}\n\
                Type: {}\n\
                Amount: ${:.2}\n\
                Account: {}{}\n\
                Date/Time: {}\n\
                Status: {}\n\
                ====================\n\
                This receipt serves as proof of transaction.\n\
                Keep this for your records.",
                receipt_id,
                transaction.id,
                reference,
                transaction_type_str,
                transaction.amount,
                transaction.account_id,
                transfer_details,
                formatted_timestamp,
                transaction.status.as_str().to_uppercase()
            );
            
            // In a real system, we might store this receipt in the database
            // or send it to the user via email
            
            Ok(receipt)
        },
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                Err(TransactionError::Unknown("Transaction not found".to_string()))
            } else {
                Err(TransactionError::DatabaseError(e.to_string()))
            }
        }
    }
}

/// Cancel a scheduled transaction before it executes
pub fn cancel_scheduled_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    scheduled_id: &str,
) -> Result<(), TransactionError> {
    // Check if the scheduled transaction exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT processed FROM scheduled_transactions WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let processed_result = stmt.query_row(params![scheduled_id, auth_result.user_id], |row| {
        let processed: bool = row.get(0)?;
        Ok(processed)
    });
    
    match processed_result {
        Ok(processed) => {
            if processed {
                return Err(TransactionError::Unknown("Transaction already processed and cannot be cancelled".to_string()));
            }
            
            // Cancel the scheduled transaction
            conn.execute(
                "UPDATE scheduled_transactions SET cancelled = 1, cancelled_at = ?1 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), scheduled_id],
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            // Create audit log
            let audit_log = AuditLog::new(
                AuditEventType::TransactionCancelled,
                Some(auth_result.user_id.to_string()),
                Some(format!("Cancelled scheduled transaction {}", scheduled_id)),
            );
            
            conn.execute(
                "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    audit_log.id,
                    audit_log.event_type.as_str(),
                    audit_log.user_id,
                    audit_log.details,
                    audit_log.timestamp,
                ],
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            info!("Scheduled transaction {} cancelled successfully", scheduled_id);
            Ok(())
        },
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                Err(TransactionError::Unknown("Scheduled transaction not found or not authorized".to_string()))
            } else {
                Err(TransactionError::DatabaseError(e.to_string()))
            }
        }
    }
}

/// Cancel a recurring transaction series
pub fn cancel_recurring_transaction(
    conn: &Connection,
    auth_result: &AuthResult,
    recurring_id: &str,
) -> Result<(), TransactionError> {
    // Check if the recurring transaction exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT completed FROM recurring_transactions WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
    
    let completed_result = stmt.query_row(params![recurring_id, auth_result.user_id], |row| {
        let completed: bool = row.get(0)?;
        Ok(completed)
    });
    
    match completed_result {
        Ok(completed) => {
            if completed {
                return Err(TransactionError::Unknown("Recurring transaction series already completed".to_string()));
            }
            
            // Cancel the recurring transaction
            conn.execute(
                "UPDATE recurring_transactions SET cancelled = 1, cancelled_at = ?1 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), recurring_id],
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            // Create audit log
            let audit_log = AuditLog::new(
                AuditEventType::RecurringTransactionCancelled,
                Some(auth_result.user_id.to_string()),
                Some(format!("Cancelled recurring transaction {}", recurring_id)),
            );
            
            conn.execute(
                "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    audit_log.id,
                    audit_log.event_type.as_str(),
                    audit_log.user_id,
                    audit_log.details,
                    audit_log.timestamp,
                ],
            ).map_err(|e| TransactionError::DatabaseError(e.to_string()))?;
            
            info!("Recurring transaction {} cancelled successfully", recurring_id);
            Ok(())
        },
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                Err(TransactionError::Unknown("Recurring transaction not found or not authorized".to_string()))
            } else {
                Err(TransactionError::DatabaseError(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use chrono::{Duration as ChronoDuration, Utc};
    use crate::database::schema::create_tables;
    use crate::security::encryption;
    use crate::security::auth::AuthResult;
    use crate::database::models::{AccountType, AccountStatus};
    
    // Helper function to set up a test database
    fn setup_test_db() -> (Connection, TempDir) {
        // Initialize encryption
        let _ = encryption::initialize();
        
        // Create a temporary directory for test DB
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_bank.db");
        
        // Create a new database connection
        let conn = Connection::open(&db_path).unwrap();
        
        // Create tables
        create_tables(&conn).unwrap();
        
        // Create a test user
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
                             account_locked, created_at, updated_at)
            VALUES ('user1', 'testuser', 'hash', 'salt', 'user', 0, 0, 
                    datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        
        // Create a test admin user
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
                             account_locked, created_at, updated_at)
            VALUES ('admin1', 'admin', 'hash', 'salt', 'admin', 0, 0, 
                    datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        
        // Create test accounts
        conn.execute(
            "INSERT INTO accounts (id, user_id, account_type, balance, status, created_at, updated_at)
            VALUES ('account1', 'user1', 'checking', 1000.00, 'active', 
                    datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        
        conn.execute(
            "INSERT INTO accounts (id, user_id, account_type, balance, status, created_at, updated_at)
            VALUES ('account2', 'user1', 'savings', 2000.00, 'active', 
                    datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_process_transaction() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Process a deposit transaction
        let result = process_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            100.0,
            Some("Test deposit"),
        );
        
        assert!(result.is_ok(), "Transaction should succeed: {:?}", result.err());
        
        // Check that the balance was updated
        let balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(balance, 1100.0, "Balance should be updated to 1100.0");
        
        // Check that transaction record was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM transactions WHERE account_id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One transaction record should be created");
        
        // Check that audit log was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = ?1",
            params![AuditEventType::TransactionCreated.as_str()],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One audit log record should be created");
    }
    
    #[test]
    fn test_process_withdrawal_with_insufficient_funds() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Try to withdraw more than available balance
        let result = process_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Withdrawal,
            1500.0,
            Some("Test withdrawal"),
        );
        
        assert!(result.is_err(), "Transaction should fail");
        
        match result.unwrap_err() {
            TransactionError::InsufficientFunds => {},
            err => panic!("Expected InsufficientFunds error, got: {:?}", err),
        }
        
        // Check that the balance was not changed
        let balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(balance, 1000.0, "Balance should remain 1000.0");
    }
    
    #[test]
    fn test_transfer_funds() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // First mark the user as having 2FA verified
        conn.execute(
            "INSERT INTO verified_operations (user_id, operation, verified_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                "user1", 
                "transfer_funds", 
                Utc::now().to_rfc3339(), 
                (Utc::now() + ChronoDuration::minutes(15)).to_rfc3339()
            ],
        ).unwrap();
        
        // Process a transfer
        let result = transfer_funds(
            &conn,
            &auth_result,
            "account1", // from
            "account2", // to
            200.0,
            Some("Test transfer"),
        );
        
        assert!(result.is_ok(), "Transfer should succeed: {:?}", result.err());
        
        // Check that the balances were updated
        let from_balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        let to_balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account2"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(from_balance, 800.0, "From account balance should be 800.0");
        assert_eq!(to_balance, 2200.0, "To account balance should be 2200.0");
        
        // Check that transaction record was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM transactions WHERE transaction_type = ?1",
            params![TransactionType::Transfer.as_str()],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One transfer record should be created");
    }
    
    #[test]
    fn test_transfer_requires_2fa() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Process a transfer without 2FA verification
        let result = transfer_funds(
            &conn,
            &auth_result,
            "account1", // from
            "account2", // to
            200.0,
            Some("Test transfer"),
        );
        
        assert!(result.is_err(), "Transfer should fail without 2FA");
        
        match result.unwrap_err() {
            TransactionError::TwoFactorRequired(_) => {},
            err => panic!("Expected TwoFactorRequired error, got: {:?}", err),
        }
        
        // Check that the balances were not updated
        let from_balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        let to_balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account2"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(from_balance, 1000.0, "From account balance should still be 1000.0");
        assert_eq!(to_balance, 2000.0, "To account balance should still be 2000.0");
    }
    
    #[test]
    fn test_scheduled_transaction() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Schedule a transaction for tomorrow
        let future_date = Utc::now() + ChronoDuration::days(1);
        let result = schedule_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            300.0,
            future_date,
            Some("Scheduled deposit"),
            None,
        );
        
        assert!(result.is_ok(), "Scheduling should succeed: {:?}", result.err());
        
        // Check that scheduled transaction record was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scheduled_transactions",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One scheduled transaction record should be created");
        
        // Check that the transaction hasn't been processed yet
        let processed: bool = conn.query_row(
            "SELECT processed FROM scheduled_transactions LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(processed, false, "Transaction should not be processed yet");
        
        // Check that audit log was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type = ?1",
            params![AuditEventType::TransactionScheduled.as_str()],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One audit log record should be created");
    }
    
    #[test]
    fn test_process_scheduled_transactions() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Schedule a transaction for the past
        let past_date = Utc::now() - ChronoDuration::hours(1);
        let result = schedule_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            300.0,
            past_date,
            Some("Past scheduled deposit"),
            None,
        );
        
        assert!(result.is_ok(), "Scheduling should succeed");
        
        // Schedule a transaction for the future
        let future_date = Utc::now() + ChronoDuration::days(1);
        let result = schedule_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            400.0,
            future_date,
            Some("Future scheduled deposit"),
            None,
        );
        
        assert!(result.is_ok(), "Scheduling should succeed");
        
        // Process scheduled transactions
        let processed = process_scheduled_transactions(&conn);
        assert!(processed.is_ok(), "Processing should succeed");
        assert_eq!(processed.unwrap(), 1, "Only one transaction should be processed");
        
        // Check that the past transaction was processed
        let processed_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scheduled_transactions WHERE processed = 1",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(processed_count, 1, "One scheduled transaction should be marked as processed");
        
        // Check that the account balance was updated
        let balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(balance, 1300.0, "Balance should be updated to 1300.0");
        
        // Check that a transaction record was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM transactions WHERE account_id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One transaction record should be created");
    }
    
    #[test]
    fn test_recurring_transaction() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Create a monthly recurring transaction starting from yesterday
        let start_date = Utc::now() - ChronoDuration::days(1);
        let end_date = Utc::now() + ChronoDuration::days(90); // 3 months out
        
        let result = create_recurring_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            200.0,
            RecurrenceFrequency::Monthly,
            start_date,
            Some(end_date),
            Some("Monthly deposit"),
            None,
        );
        
        assert!(result.is_ok(), "Creating recurring transaction should succeed: {:?}", result.err());
        
        // Check that the recurring transaction record was created
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM recurring_transactions",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(count, 1, "One recurring transaction record should be created");
        
        // Process scheduled transactions (which includes recurring ones)
        let processed = process_scheduled_transactions(&conn);
        assert!(processed.is_ok(), "Processing should succeed");
        assert_eq!(processed.unwrap(), 1, "One transaction should be processed");
        
        // Check that the account balance was updated
        let balance: f64 = conn.query_row(
            "SELECT balance FROM accounts WHERE id = ?1",
            params!["account1"],
            |row| row.get(0),
        ).unwrap();
        
        assert_eq!(balance, 1200.0, "Balance should be updated to 1200.0");
        
        // Check that the next_date was updated (roughly 30 days later)
        let next_date: String = conn.query_row(
            "SELECT next_date FROM recurring_transactions LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert!(next_date > start_date.to_rfc3339(), "Next date should be updated to a future date");
    }
    
    #[test]
    fn test_encryption_of_transaction_details() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an auth result for testing
        let auth_result = AuthResult {
            user_id: "user1".to_string(),
            username: "testuser".to_string(),
            role: "user".to_string(),
            permissions: vec!["transaction.create".to_string()],
            token: None,
        };
        
        // Create a transaction with details to be encrypted
        let sensitive_details = "SENSITIVE: Account number 123456789";
        let result = process_transaction(
            &conn,
            &auth_result,
            "account1",
            TransactionType::Deposit,
            100.0,
            Some(sensitive_details),
        );
        
        assert!(result.is_ok(), "Transaction should succeed");
        
        // Get the encrypted details from the database
        let encrypted_details: Option<String> = conn.query_row(
            "SELECT encrypted_details FROM transactions LIMIT 1",
            [],
            |row| row.get(0),
        ).unwrap();
        
        assert!(encrypted_details.is_some(), "Encrypted details should be stored");
        
        // Verify the details are actually encrypted
        let encrypted = encrypted_details.unwrap();
        assert_ne!(encrypted, sensitive_details, "Details should be encrypted, not stored as plaintext");
        
        // Try to decrypt the details
        let decrypted = decrypt_transaction_details(&encrypted);
        assert!(decrypted.is_ok(), "Decryption should succeed");
        assert_eq!(decrypted.unwrap(), sensitive_details, "Decrypted content should match original");
    }
} 