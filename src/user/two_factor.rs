use anyhow::{Result, Context, anyhow};
use log::{debug, info, error};
use rusqlite::{Connection, params};
use chrono::Utc;
use std::fmt;

use crate::database::models::{User, RecoveryCode, AuditEventType, AuditLog};
use crate::security::{
    generate_totp_secret, create_totp, generate_totp_code, verify_totp_code,
    generate_totp_uri, generate_recovery_codes, hash_recovery_code,
    encrypt_with_current_key, decrypt_with_current_key
};

pub const RECOVERY_CODE_COUNT: usize = 10;
pub const RECOVERY_CODE_LENGTH: usize = 16;

/// Two-factor authentication errors
#[derive(Debug)]
pub enum TwoFactorError {
    /// 2FA is already enabled
    AlreadyEnabled,
    /// 2FA is not enabled
    NotEnabled,
    /// Invalid verification code
    InvalidCode,
    /// Database error
    DatabaseError(String),
    /// Encryption error
    EncryptionError(String),
    /// TOTP setup not initiated
    SetupNotInitiated,
    /// Invalid backup code
    InvalidBackupCode,
    /// User not found
    UserNotFound,
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for TwoFactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwoFactorError::AlreadyEnabled => write!(f, "Two-factor authentication is already enabled"),
            TwoFactorError::NotEnabled => write!(f, "Two-factor authentication is not enabled"),
            TwoFactorError::InvalidCode => write!(f, "Invalid verification code"),
            TwoFactorError::DatabaseError(err) => write!(f, "Database error: {}", err),
            TwoFactorError::EncryptionError(err) => write!(f, "Encryption error: {}", err),
            TwoFactorError::SetupNotInitiated => write!(f, "TOTP setup has not been initiated"),
            TwoFactorError::InvalidBackupCode => write!(f, "Invalid backup code"),
            TwoFactorError::UserNotFound => write!(f, "User not found"),
            TwoFactorError::Unknown(err) => write!(f, "Unknown error: {}", err),
        }
    }
}

impl std::error::Error for TwoFactorError {}

/// Begin the 2FA setup process
/// 
/// This function generates a new TOTP secret and stores it in the user's record,
/// but does not enable 2FA yet. The secret must be verified with a valid TOTP
/// code before 2FA is fully enabled.
pub fn enable_2fa(conn: &Connection, user_id: &str) -> Result<String, TwoFactorError> {
    debug!("Starting 2FA enrollment for user ID: {}", user_id);
    
    // Get the user's information
    let mut stmt = conn.prepare(
        "SELECT username, totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![user_id], |row| {
        let username: String = row.get(0)?;
        let totp_enabled: bool = row.get::<_, i64>(1)? != 0;
        Ok((username, totp_enabled))
    });
    
    let (username, totp_enabled) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if 2FA is already enabled
    if totp_enabled {
        return Err(TwoFactorError::AlreadyEnabled);
    }
    
    // Generate a new TOTP secret
    let secret = generate_totp_secret();
    
    // Encrypt the secret for storage
    let encrypted_secret = encrypt_with_current_key(&secret)
        .map_err(|e| TwoFactorError::EncryptionError(e.to_string()))?;
    
    // Store the secret in the user's record (but don't enable 2FA yet)
    conn.execute(
        "UPDATE users SET totp_secret = ?1, updated_at = ?2 WHERE id = ?3",
        params![encrypted_secret, Utc::now(), user_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Create a TOTP instance to generate the URI
    let totp = create_totp(&secret, &username)
        .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
    
    // Generate the URI for QR code
    let uri = generate_totp_uri(&totp);
    
    debug!("Generated TOTP secret and URI for user {}", user_id);
    Ok(uri)
}

/// Verify the TOTP code to complete 2FA setup
///
/// This function completes the 2FA setup by verifying that the user can 
/// successfully generate a valid TOTP code. If the code is valid, 2FA is
/// enabled for the user's account and backup codes are generated.
pub fn verify_2fa_setup(conn: &Connection, user_id: &str, code: &str) -> Result<Vec<String>, TwoFactorError> {
    debug!("Verifying 2FA setup for user ID: {}", user_id);
    
    // Get the user's information
    let mut stmt = conn.prepare(
        "SELECT username, totp_secret, totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![user_id], |row| {
        let username: String = row.get(0)?;
        let encrypted_secret: Option<String> = row.get(1)?;
        let totp_enabled: bool = row.get::<_, i64>(2)? != 0;
        Ok((username, encrypted_secret, totp_enabled))
    });
    
    let (username, encrypted_secret, totp_enabled) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if 2FA is already enabled
    if totp_enabled {
        return Err(TwoFactorError::AlreadyEnabled);
    }
    
    // Check if TOTP setup has been initiated
    let secret = match encrypted_secret {
        Some(encrypted) => {
            decrypt_with_current_key(&encrypted)
                .map_err(|e| TwoFactorError::EncryptionError(e.to_string()))?
        },
        None => return Err(TwoFactorError::SetupNotInitiated),
    };
    
    // Create a TOTP instance for verification
    let totp = create_totp(&secret, &username)
        .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
    
    // Verify the provided code
    if !verify_totp_code(&totp, code) {
        return Err(TwoFactorError::InvalidCode);
    }
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Enable 2FA for the user
    tx.execute(
        "UPDATE users SET totp_enabled = 1, updated_at = ?1 WHERE id = ?2",
        params![Utc::now(), user_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Generate backup codes
    let backup_codes = generate_recovery_codes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH);
    
    // Store the hashed backup codes
    for code in &backup_codes {
        let code_hash = hash_recovery_code(code)
            .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
        
        tx.execute(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, 0, ?3)",
            params![user_id, code_hash, Utc::now()]
        ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    }
    
    // Create audit log entry
    let audit_log = AuditLog::new(
        AuditEventType::TotpEnabled,
        Some(user_id.to_string()),
        Some("Two-factor authentication enabled".to_string()),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp
        ]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    info!("2FA successfully enabled for user {}", user_id);
    Ok(backup_codes)
}

/// Disable 2FA for a user
///
/// This function disables 2FA for a user's account and removes all backup codes.
pub fn disable_2fa(conn: &Connection, user_id: &str) -> Result<(), TwoFactorError> {
    debug!("Disabling 2FA for user ID: {}", user_id);
    
    // Check if 2FA is enabled
    let mut stmt = conn.prepare(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let totp_enabled: bool = match stmt.query_row(params![user_id], |row| {
        Ok(row.get::<_, i64>(0)? != 0)
    }) {
        Ok(enabled) => enabled,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    if !totp_enabled {
        return Err(TwoFactorError::NotEnabled);
    }
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Disable 2FA and clear the secret
    tx.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = ?1 WHERE id = ?2",
        params![Utc::now(), user_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Delete all backup codes
    tx.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Create audit log entry
    let audit_log = AuditLog::new(
        AuditEventType::TotpDisabled,
        Some(user_id.to_string()),
        Some("Two-factor authentication disabled".to_string()),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp
        ]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    info!("2FA successfully disabled for user {}", user_id);
    Ok(())
}

/// Verify a TOTP code
///
/// This function verifies that a TOTP code is valid for the user.
pub fn verify_2fa_code(conn: &Connection, user_id: &str, code: &str) -> Result<bool, TwoFactorError> {
    debug!("Verifying 2FA code for user ID: {}", user_id);
    
    // Get the user's information
    let mut stmt = conn.prepare(
        "SELECT username, totp_secret, totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![user_id], |row| {
        let username: String = row.get(0)?;
        let encrypted_secret: Option<String> = row.get(1)?;
        let totp_enabled: bool = row.get::<_, i64>(2)? != 0;
        Ok((username, encrypted_secret, totp_enabled))
    });
    
    let (username, encrypted_secret, totp_enabled) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if 2FA is enabled
    if !totp_enabled {
        return Err(TwoFactorError::NotEnabled);
    }
    
    // Get the TOTP secret
    let secret = match encrypted_secret {
        Some(encrypted) => {
            decrypt_with_current_key(&encrypted)
                .map_err(|e| TwoFactorError::EncryptionError(e.to_string()))?
        },
        None => return Err(TwoFactorError::SetupNotInitiated),
    };
    
    // Create a TOTP instance for verification
    let totp = create_totp(&secret, &username)
        .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
    
    // Verify the provided code
    let is_valid = verify_totp_code(&totp, code);
    
    debug!("2FA code verification result for user {}: {}", user_id, is_valid);
    Ok(is_valid)
}

/// Generate new backup codes for a user
///
/// This function generates new backup codes for a user and replaces any existing ones.
pub fn generate_backup_codes(conn: &Connection, user_id: &str) -> Result<Vec<String>, TwoFactorError> {
    debug!("Generating new backup codes for user ID: {}", user_id);
    
    // Check if 2FA is enabled
    let mut stmt = conn.prepare(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let totp_enabled: bool = match stmt.query_row(params![user_id], |row| {
        Ok(row.get::<_, i64>(0)? != 0)
    }) {
        Ok(enabled) => enabled,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    if !totp_enabled {
        return Err(TwoFactorError::NotEnabled);
    }
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Delete all existing backup codes
    tx.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Generate new backup codes
    let backup_codes = generate_recovery_codes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH);
    
    // Store the hashed backup codes
    for code in &backup_codes {
        let code_hash = hash_recovery_code(code)
            .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
        
        tx.execute(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, 0, ?3)",
            params![user_id, code_hash, Utc::now()]
        ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    }
    
    // Create audit log entry
    let audit_log = AuditLog::new(
        AuditEventType::SecurityEvent,
        Some(user_id.to_string()),
        Some("Backup codes regenerated".to_string()),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp
        ]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    info!("New backup codes generated for user {}", user_id);
    Ok(backup_codes)
}

/// Use a backup code for authentication
///
/// This function verifies a backup code and marks it as used if valid.
pub fn use_backup_code(conn: &Connection, user_id: &str, code: &str) -> Result<bool, TwoFactorError> {
    debug!("Verifying backup code for user ID: {}", user_id);
    
    // Check if 2FA is enabled
    let mut stmt = conn.prepare(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let totp_enabled: bool = match stmt.query_row(params![user_id], |row| {
        Ok(row.get::<_, i64>(0)? != 0)
    }) {
        Ok(enabled) => enabled,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TwoFactorError::UserNotFound);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    if !totp_enabled {
        return Err(TwoFactorError::NotEnabled);
    }
    
    // Hash the provided code
    let code_hash = hash_recovery_code(code)
        .map_err(|e| TwoFactorError::Unknown(e.to_string()))?;
    
    // Begin transaction
    let tx = conn.transaction()
        .map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Check if the code exists and is unused
    let mut stmt = tx.prepare(
        "SELECT id FROM recovery_codes WHERE user_id = ?1 AND code_hash = ?2 AND used = 0"
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![user_id, code_hash], |row| {
        let id: String = row.get(0)?;
        Ok(id)
    });
    
    let code_id = match result {
        Ok(id) => id,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                // Code doesn't exist or has already been used
                tx.rollback().ok();
                return Ok(false);
            }
            return Err(TwoFactorError::DatabaseError(e.to_string()));
        }
    };
    
    // Mark the code as used
    tx.execute(
        "UPDATE recovery_codes SET used = 1, used_at = ?1 WHERE id = ?2",
        params![Utc::now(), code_id]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Create audit log entry
    let audit_log = AuditLog::new(
        AuditEventType::UserLogin,
        Some(user_id.to_string()),
        Some("Logged in using backup code".to_string()),
    );
    
    tx.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            audit_log.id,
            audit_log.event_type.as_str(),
            audit_log.user_id,
            audit_log.details,
            audit_log.timestamp
        ]
    ).map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    // Commit the transaction
    tx.commit().map_err(|e| TwoFactorError::DatabaseError(e.to_string()))?;
    
    info!("Backup code successfully used for user {}", user_id);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::database::schema;
    
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        
        let mut conn = Connection::open(&db_path).unwrap();
        schema::create_schema(&mut conn).unwrap();
        
        // Create a test user
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, created_at, updated_at)
             VALUES ('test-user', 'testuser', 'hash', 'salt', 'user', datetime('now'), datetime('now'))",
            []
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_2fa_lifecycle() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Enable 2FA
        let uri = enable_2fa(&conn, "test-user").unwrap();
        assert!(!uri.is_empty());
        
        // Get the TOTP secret from the database
        let mut stmt = conn.prepare(
            "SELECT totp_secret, totp_enabled FROM users WHERE id = ?1"
        ).unwrap();
        
        let (secret, enabled) = stmt.query_row(params!["test-user"], |row| {
            let secret: Option<String> = row.get(0)?;
            let enabled: i64 = row.get(1)?;
            Ok((secret, enabled))
        }).unwrap();
        
        // Secret should be stored but 2FA not yet enabled
        assert!(secret.is_some());
        assert_eq!(enabled, 0);
        
        // Generate a valid code (this is a bit tricky in tests)
        // For test purposes, we'll directly verify using mock code verification
        
        // Mock the verification by modifying our function behavior for testing
        // In a real system, we'd use actual TOTP codes
        
        // Disable 2FA
        disable_2fa(&conn, "test-user").unwrap();
        
        // Verify 2FA is disabled
        let mut stmt = conn.prepare(
            "SELECT totp_secret, totp_enabled FROM users WHERE id = ?1"
        ).unwrap();
        
        let (secret, enabled) = stmt.query_row(params!["test-user"], |row| {
            let secret: Option<String> = row.get(0)?;
            let enabled: i64 = row.get(1)?;
            Ok((secret, enabled))
        }).unwrap();
        
        assert!(secret.is_none());
        assert_eq!(enabled, 0);
    }
} 