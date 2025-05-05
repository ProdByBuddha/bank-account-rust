use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn};
use rusqlite::Connection;
use std::fmt;
use std::collections::HashSet;

use crate::database::models::{AuditEventType, AuditLog};
use crate::security::auth::AuthResult;
use crate::user::TwoFactorError;

/// Enum defining the types of sensitive operations that require 2FA verification
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum SensitiveOperation {
    /// Transferring money to another account
    TransferFunds,
    /// Changing user profile information
    ChangeProfile,
    /// Changing passwords
    ChangePassword,
    /// Adding or removing account access
    ManageAccounts,
    /// Modifying security settings
    ChangeSecuritySettings,
    /// Performing admin actions
    AdminAction,
}

impl SensitiveOperation {
    /// Convert operation to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitiveOperation::TransferFunds => "transfer_funds",
            SensitiveOperation::ChangeProfile => "change_profile",
            SensitiveOperation::ChangePassword => "change_password",
            SensitiveOperation::ManageAccounts => "manage_accounts",
            SensitiveOperation::ChangeSecuritySettings => "change_security_settings",
            SensitiveOperation::AdminAction => "admin_action",
        }
    }
    
    /// Convert from string to operation type
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "transfer_funds" => Ok(SensitiveOperation::TransferFunds),
            "change_profile" => Ok(SensitiveOperation::ChangeProfile),
            "change_password" => Ok(SensitiveOperation::ChangePassword),
            "manage_accounts" => Ok(SensitiveOperation::ManageAccounts),
            "change_security_settings" => Ok(SensitiveOperation::ChangeSecuritySettings),
            "admin_action" => Ok(SensitiveOperation::AdminAction),
            _ => Err(format!("Invalid sensitive operation type: {}", s)),
        }
    }
    
    /// Get a friendly name for the operation
    pub fn friendly_name(&self) -> &'static str {
        match self {
            SensitiveOperation::TransferFunds => "Transfer Funds",
            SensitiveOperation::ChangeProfile => "Change Profile Information",
            SensitiveOperation::ChangePassword => "Change Password",
            SensitiveOperation::ManageAccounts => "Manage Account Access",
            SensitiveOperation::ChangeSecuritySettings => "Change Security Settings",
            SensitiveOperation::AdminAction => "Admin Action",
        }
    }
}

/// Error for sensitive operations
#[derive(Debug)]
pub enum SensitiveOperationError {
    /// Two-factor authentication is not enabled for the user
    TwoFactorNotEnabled,
    /// Invalid 2FA code provided
    InvalidCode,
    /// Two-factor authentication required
    TwoFactorRequired,
    /// Database error
    DatabaseError(String),
    /// User not found
    UserNotFound,
    /// Session verification expired
    VerificationExpired,
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for SensitiveOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensitiveOperationError::TwoFactorNotEnabled => {
                write!(f, "Two-factor authentication is not enabled for this user")
            }
            SensitiveOperationError::InvalidCode => {
                write!(f, "Invalid verification code")
            }
            SensitiveOperationError::TwoFactorRequired => {
                write!(f, "Two-factor authentication is required for this operation")
            }
            SensitiveOperationError::DatabaseError(err) => {
                write!(f, "Database error: {}", err)
            }
            SensitiveOperationError::UserNotFound => {
                write!(f, "User not found")
            }
            SensitiveOperationError::VerificationExpired => {
                write!(f, "2FA verification has expired, please verify again")
            }
            SensitiveOperationError::Unknown(err) => {
                write!(f, "Unknown error: {}", err)
            }
        }
    }
}

impl std::error::Error for SensitiveOperationError {}

impl From<TwoFactorError> for SensitiveOperationError {
    fn from(error: TwoFactorError) -> Self {
        match error {
            TwoFactorError::NotEnabled => SensitiveOperationError::TwoFactorNotEnabled,
            TwoFactorError::InvalidCode => SensitiveOperationError::InvalidCode,
            TwoFactorError::UserNotFound => SensitiveOperationError::UserNotFound,
            TwoFactorError::DatabaseError(err) => SensitiveOperationError::DatabaseError(err),
            _ => SensitiveOperationError::Unknown(error.to_string()),
        }
    }
}

/// Time window in seconds for which a 2FA verification is valid
const VERIFICATION_WINDOW_SECONDS: i64 = 300; // 5 minutes

/// Get configuration for which operations require 2FA verification
pub fn get_required_2fa_operations(conn: &Connection) -> Result<HashSet<SensitiveOperation>, SensitiveOperationError> {
    // In a full implementation, this might be configurable by admin or read from a database
    // For now, we'll return a hardcoded set of operations that require 2FA
    
    let mut operations = HashSet::new();
    operations.insert(SensitiveOperation::TransferFunds);
    operations.insert(SensitiveOperation::ChangePassword);
    operations.insert(SensitiveOperation::ManageAccounts);
    operations.insert(SensitiveOperation::ChangeSecuritySettings);
    operations.insert(SensitiveOperation::AdminAction);
    
    Ok(operations)
}

/// Check if a sensitive operation requires 2FA verification
pub fn requires_2fa_verification(
    conn: &Connection,
    operation: SensitiveOperation,
) -> Result<bool, SensitiveOperationError> {
    let required_operations = get_required_2fa_operations(conn)?;
    Ok(required_operations.contains(&operation))
}

/// Verify 2FA code for a sensitive operation
pub fn verify_for_sensitive_operation(
    conn: &Connection,
    user_id: &str,
    code: &str,
    operation: SensitiveOperation,
) -> Result<(), SensitiveOperationError> {
    // First check if this operation requires 2FA
    if !requires_2fa_verification(conn, operation)? {
        return Ok(());
    }
    
    // Verify the 2FA code
    match crate::user::verify_2fa_code(conn, user_id, code) {
        Ok(true) => {
            // Create an entry in the recent_verifications table
            let now = chrono::Utc::now();
            
            conn.execute(
                "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
                 VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3)",
                rusqlite::params![user_id, operation.as_str(), now],
            ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
            
            // Log the verification
            let audit_log = AuditLog::new(
                AuditEventType::SensitiveOpVerified,
                Some(user_id.to_string()),
                Some(format!("2FA verified for operation: {}", operation.friendly_name())),
            );
            
            conn.execute(
                "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    audit_log.id,
                    audit_log.event_type.as_str(),
                    audit_log.user_id,
                    audit_log.details,
                    audit_log.timestamp
                ],
            ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
            
            info!("2FA verification successful for user {} for operation {}", 
                user_id, operation.as_str());
            
            Ok(())
        },
        Ok(false) => Err(SensitiveOperationError::InvalidCode),
        Err(err) => Err(err.into()),
    }
}

/// Check if a user has recently verified 2FA for a sensitive operation
pub fn has_recent_verification(
    conn: &Connection,
    user_id: &str,
    operation: SensitiveOperation,
) -> Result<bool, SensitiveOperationError> {
    debug!("Checking for recent 2FA verification for user {} and operation {}", 
        user_id, operation.as_str());
    
    // First check if this operation requires 2FA
    if !requires_2fa_verification(conn, operation)? {
        return Ok(true); // No 2FA needed for this operation
    }
    
    // Check if user has 2FA enabled
    let mut stmt = conn.prepare(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
    
    let totp_enabled: bool = match stmt.query_row(rusqlite::params![user_id], |row| {
        Ok(row.get::<_, i64>(0)? != 0)
    }) {
        Ok(enabled) => enabled,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(SensitiveOperationError::UserNotFound);
            }
            return Err(SensitiveOperationError::DatabaseError(e.to_string()));
        }
    };
    
    if !totp_enabled {
        debug!("User {} does not have 2FA enabled", user_id);
        return Err(SensitiveOperationError::TwoFactorNotEnabled);
    }
    
    // Check for recent verification
    let now = chrono::Utc::now();
    let verification_window = chrono::Duration::seconds(VERIFICATION_WINDOW_SECONDS);
    let cutoff_time = now - verification_window;
    
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM recent_verifications 
         WHERE user_id = ?1 
         AND (operation = ?2 OR operation = 'admin_action') 
         AND verified_at > ?3"
    ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
    
    let count: i64 = stmt.query_row(
        rusqlite::params![user_id, operation.as_str(), cutoff_time],
        |row| row.get(0),
    ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
    
    debug!("Found {} recent verifications for user {} and operation {}", 
        count, user_id, operation.as_str());
    
    Ok(count > 0)
}

/// Require 2FA verification for a sensitive operation
pub fn require_verification_for_operation(
    conn: &Connection,
    auth_result: &AuthResult,
    operation: SensitiveOperation,
) -> Result<(), SensitiveOperationError> {
    // Skip verification if user doesn't have 2FA enabled
    let user_id = &auth_result.user_id;
    
    let mut stmt = conn.prepare(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| SensitiveOperationError::DatabaseError(e.to_string()))?;
    
    let totp_enabled: bool = match stmt.query_row(rusqlite::params![user_id], |row| {
        Ok(row.get::<_, i64>(0)? != 0)
    }) {
        Ok(enabled) => enabled,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(SensitiveOperationError::UserNotFound);
            }
            return Err(SensitiveOperationError::DatabaseError(e.to_string()));
        }
    };
    
    if !totp_enabled {
        // User doesn't have 2FA enabled, so no verification required
        debug!("User {} does not have 2FA enabled, skipping verification for {}", 
            user_id, operation.as_str());
        return Ok(());
    }
    
    // Check if operation requires 2FA
    if !requires_2fa_verification(conn, operation)? {
        debug!("Operation {} does not require 2FA verification", operation.as_str());
        return Ok(());
    }
    
    // Check if user has a recent verification
    if has_recent_verification(conn, user_id, operation)? {
        debug!("User {} has recent 2FA verification for operation {}", 
            user_id, operation.as_str());
        return Ok(());
    }
    
    // No recent verification found, require 2FA
    warn!("User {} needs 2FA verification for operation {}", 
        user_id, operation.as_str());
    
    Err(SensitiveOperationError::TwoFactorRequired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::database::init_database;
    use crate::security::auth::AuthResult;
    use crate::database::models::UserRole;
    use chrono::Utc;
    
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
        
        // Add a test user with 2FA enabled
        conn.execute(
            "INSERT INTO users (
                id, username, password_hash, email, role, 
                account_locked, failed_login_attempts, created_at, updated_at,
                last_login, password_changed, totp_secret, totp_enabled
            ) VALUES (
                'test-user-id', 'testuser', 'hash', 'test@example.com', 'regular',
                0, 0, datetime('now'), datetime('now'),
                datetime('now'), datetime('now'), 'encrypted-secret', 1
            )",
            [],
        ).unwrap();
        
        // Add a test user without 2FA enabled
        conn.execute(
            "INSERT INTO users (
                id, username, password_hash, email, role, 
                account_locked, failed_login_attempts, created_at, updated_at,
                last_login, password_changed, totp_secret, totp_enabled
            ) VALUES (
                'test-user-id-no-2fa', 'testuser2', 'hash', 'test2@example.com', 'regular',
                0, 0, datetime('now'), datetime('now'),
                datetime('now'), datetime('now'), NULL, 0
            )",
            [],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_requires_2fa_verification() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Test that certain operations require 2FA
        assert!(requires_2fa_verification(&conn, SensitiveOperation::TransferFunds).unwrap());
        assert!(requires_2fa_verification(&conn, SensitiveOperation::ChangePassword).unwrap());
        assert!(requires_2fa_verification(&conn, SensitiveOperation::AdminAction).unwrap());
    }
    
    #[test]
    fn test_has_recent_verification() {
        let (conn, _temp_dir) = setup_test_db();
        let user_id = "test-user-id";
        let operation = SensitiveOperation::TransferFunds;
        
        // Initially, user should have no recent verification
        assert!(!has_recent_verification(&conn, user_id, operation).unwrap());
        
        // Add a recent verification
        let now = Utc::now();
        conn.execute(
            "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
             VALUES ('test-verif-id', ?1, ?2, ?3)",
            rusqlite::params![user_id, operation.as_str(), now],
        ).unwrap();
        
        // Now user should have a recent verification
        assert!(has_recent_verification(&conn, user_id, operation).unwrap());
        
        // Test with user that doesn't have 2FA enabled
        let user_without_2fa = "test-user-id-no-2fa";
        let result = has_recent_verification(&conn, user_without_2fa, operation);
        assert!(matches!(result, Err(SensitiveOperationError::TwoFactorNotEnabled)));
    }
    
    #[test]
    fn test_require_verification_for_operation() {
        let (conn, _temp_dir) = setup_test_db();
        let user_id = "test-user-id";
        let operation = SensitiveOperation::TransferFunds;
        
        // Create auth result for testing
        let auth_result = AuthResult {
            user_id: user_id.to_string(),
            username: "testuser".to_string(),
            role: UserRole::Regular,
            tfa_verified: true,
            token_id: "test-token".to_string(),
            last_activity: Utc::now(),
        };
        
        // Initially, should require verification
        let result = require_verification_for_operation(&conn, &auth_result, operation);
        assert!(matches!(result, Err(SensitiveOperationError::TwoFactorRequired)));
        
        // Add a recent verification
        let now = Utc::now();
        conn.execute(
            "INSERT INTO recent_verifications (id, user_id, operation, verified_at)
             VALUES ('test-verif-id', ?1, ?2, ?3)",
            rusqlite::params![user_id, operation.as_str(), now],
        ).unwrap();
        
        // Now user should not need to verify again
        assert!(require_verification_for_operation(&conn, &auth_result, operation).is_ok());
        
        // Test with a user that doesn't have 2FA enabled
        let auth_result_no_2fa = AuthResult {
            user_id: "test-user-id-no-2fa".to_string(),
            username: "testuser2".to_string(),
            role: UserRole::Regular,
            tfa_verified: false,
            token_id: "test-token-2".to_string(),
            last_activity: Utc::now(),
        };
        
        // Should not require verification for user without 2FA
        assert!(require_verification_for_operation(&conn, &auth_result_no_2fa, operation).is_ok());
    }
} 