use anyhow::{Result, Context, anyhow};
use rusqlite::{Connection, params};
use log::{debug, info, warn, error};
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

use crate::database::{self, get_connection};
use crate::database::models::{User, UserRole};
use crate::security::password::{hash_password, generate_salt};
use crate::user::validation::{validate_password, PasswordValidationError};
use crate::user::{MIN_PASSWORD_LENGTH, MAX_FAILED_LOGIN_ATTEMPTS, EMAIL_REGEX};

/// User registration error types
#[derive(Debug, thiserror::Error)]
pub enum UserRegistrationError {
    #[error("Username already exists")]
    UsernameExists,
    
    #[error("Invalid username format")]
    InvalidUsername,
    
    #[error("Invalid email format")]
    InvalidEmail,
    
    #[error("Password validation failed: {0}")]
    PasswordValidationFailed(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// User login error types
#[derive(Debug, thiserror::Error)]
pub enum UserLoginError {
    #[error("Invalid username or password")]
    InvalidCredentials,
    
    #[error("Account is locked. Please try again later or reset your password")]
    AccountLocked,
    
    #[error("Password expired. Please update your password")]
    PasswordExpired,
    
    #[error("Two-factor authentication required")]
    TwoFactorRequired,
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Register a new user
pub fn register_user(
    username: &str, 
    password: &str,
    role: UserRole,
) -> Result<User, UserRegistrationError> {
    debug!("Registering new user: {}", username);
    
    // Validate username
    if !is_valid_username(username) {
        return Err(UserRegistrationError::InvalidUsername);
    }
    
    // Validate password
    match validate_password(password, Some(username)) {
        Ok(_) => {},
        Err(PasswordValidationError::RequirementsNotMet(msg)) => {
            return Err(UserRegistrationError::PasswordValidationFailed(msg));
        },
        Err(PasswordValidationError::TooSimilarToUserInfo) => {
            return Err(UserRegistrationError::PasswordValidationFailed(
                "Password is too similar to username".to_string()
            ));
        },
        Err(e) => {
            return Err(UserRegistrationError::InternalError(e.to_string()));
        }
    }
    
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Check if username already exists
    if user_exists(&conn, username)? {
        return Err(UserRegistrationError::UsernameExists);
    }
    
    // Hash the password with Argon2id
    let (password_hash, salt) = hash_password(password, 65536).map_err(|e| {
        UserRegistrationError::InternalError(format!("Failed to hash password: {}", e))
    })?;
    
    // Create user
    let user = User::new(
        username.to_string(),
        password_hash,
        salt,
        role,
    );
    
    // Store user in database
    store_user(&conn, &user).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to store user: {}", e))
    })?;
    
    info!("User registered successfully: {}", username);
    Ok(user)
}

/// Check if username exists in the database
fn user_exists(conn: &Connection, username: &str) -> Result<bool, UserRegistrationError> {
    let result = conn.query_row(
        "SELECT 1 FROM users WHERE username = ?1",
        params![username],
        |_| Ok(true)
    );
    
    match result {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(UserRegistrationError::DatabaseError(format!("Failed to check if user exists: {}", e))),
    }
}

/// Store user in the database
fn store_user(conn: &Connection, user: &User) -> Result<(), UserRegistrationError> {
    conn.execute(
        "INSERT INTO users (
            id, username, password_hash, salt, role, 
            failed_login_attempts, account_locked, 
            lockout_time, last_login, password_changed,
            totp_secret, totp_enabled, created_at, updated_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, 
            ?6, ?7, ?8, ?9, ?10, 
            ?11, ?12, ?13, ?14
        )",
        params![
            user.id,
            user.username,
            user.password_hash,
            user.salt,
            user.role.as_str(),
            user.failed_login_attempts,
            user.account_locked as i32,
            user.lockout_time.map(|dt| dt.to_rfc3339()),
            user.last_login.map(|dt| dt.to_rfc3339()),
            user.password_changed.map(|dt| dt.to_rfc3339()),
            user.totp_secret,
            user.totp_enabled as i32,
            user.created_at.to_rfc3339(),
            user.updated_at.to_rfc3339(),
        ]
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to insert user: {}", e))
    })?;
    
    // Add audit log for user creation
    let audit_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_created",
            user.id,
            format!("User created: {}", user.username),
            now
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for user creation: {}", e);
        // Continue even if audit log fails
        UserRegistrationError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    Ok(())
}

/// Check if username format is valid
fn is_valid_username(username: &str) -> bool {
    // Username should be between 3 and 30 characters
    if username.len() < 3 || username.len() > 30 {
        return false;
    }
    
    // Username should only contain alphanumeric characters, underscores, dots, and hyphens
    let re = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    if !re.is_match(username) {
        return false;
    }
    
    // Username should not start or end with a special character
    if !username.chars().next().unwrap().is_alphanumeric() ||
       !username.chars().last().unwrap().is_alphanumeric() {
        return false;
    }
    
    true
}

/// Retrieve a user by username
pub fn get_user_by_username(username: &str) -> Result<Option<User>, UserRegistrationError> {
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    let result = conn.query_row(
        "SELECT 
            id, username, password_hash, salt, role, 
            failed_login_attempts, account_locked, lockout_time,
            last_login, password_changed, totp_secret, totp_enabled,
            created_at, updated_at
         FROM users 
         WHERE username = ?1",
        params![username],
        |row| {
            let role_str: String = row.get(4)?;
            let role = UserRole::from_str(&role_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, 
                    rusqlite::types::Type::Text, Box::new(anyhow!(e))))?;
            
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?,
                role,
                failed_login_attempts: row.get(5)?,
                account_locked: row.get::<_, i32>(6)? != 0,
                lockout_time: row.get::<_, Option<String>>(7)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                last_login: row.get::<_, Option<String>>(8)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(8, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                password_changed: row.get::<_, Option<String>>(9)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(9, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                totp_secret: row.get(10)?,
                totp_enabled: row.get::<_, i32>(11)? != 0,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(12, 
                        rusqlite::types::Type::Text, Box::new(e)))?,
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(13)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(13, 
                        rusqlite::types::Type::Text, Box::new(e)))?,
            })
        }
    );
    
    match result {
        Ok(user) => Ok(Some(user)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(UserRegistrationError::DatabaseError(format!("Failed to get user: {}", e))),
    }
}

/// Change user password
pub fn change_password(
    user_id: &str,
    old_password: &str,
    new_password: &str
) -> Result<(), UserRegistrationError> {
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Get user by ID
    let user = get_user_by_id(&conn, user_id).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get user: {}", e))
    })?;
    
    if user.is_none() {
        return Err(UserRegistrationError::InternalError("User not found".to_string()));
    }
    
    let user = user.unwrap();
    
    // Verify old password
    let is_valid = crate::security::password::verify_password(old_password, &user.password_hash)
        .map_err(|e| UserRegistrationError::InternalError(format!("Password verification error: {}", e)))?;
    
    if !is_valid {
        return Err(UserRegistrationError::PasswordValidationFailed("Current password is incorrect".to_string()));
    }
    
    // Validate new password
    match validate_password(new_password, Some(&user.username)) {
        Ok(_) => {},
        Err(PasswordValidationError::RequirementsNotMet(msg)) => {
            return Err(UserRegistrationError::PasswordValidationFailed(msg));
        },
        Err(PasswordValidationError::TooSimilarToUserInfo) => {
            return Err(UserRegistrationError::PasswordValidationFailed(
                "Password is too similar to username".to_string()
            ));
        },
        Err(e) => {
            return Err(UserRegistrationError::InternalError(e.to_string()));
        }
    }
    
    // Hash the new password
    let (password_hash, salt) = hash_password(new_password, 65536).map_err(|e| {
        UserRegistrationError::InternalError(format!("Failed to hash password: {}", e))
    })?;
    
    // Update the password in database
    let now = Utc::now();
    conn.execute(
        "UPDATE users SET 
            password_hash = ?1, 
            salt = ?2, 
            password_changed = ?3,
            updated_at = ?4,
            failed_login_attempts = 0,
            account_locked = 0,
            lockout_time = NULL
         WHERE id = ?5",
        params![
            password_hash,
            salt,
            now.to_rfc3339(),
            now.to_rfc3339(),
            user_id
        ]
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to update password: {}", e))
    })?;
    
    // Add audit log for password change
    let audit_id = Uuid::new_v4().to_string();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_password_changed",
            user_id,
            "User password changed",
            now.to_rfc3339()
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for password change: {}", e);
        // Continue even if audit log fails
        UserRegistrationError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    Ok(())
}

/// Reset a user's password (for admin or password recovery)
pub fn reset_password(
    user_id: &str,
    new_password: &str
) -> Result<(), UserRegistrationError> {
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Get user by ID
    let user = get_user_by_id(&conn, user_id).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get user: {}", e))
    })?;
    
    if user.is_none() {
        return Err(UserRegistrationError::InternalError("User not found".to_string()));
    }
    
    let user = user.unwrap();
    
    // Validate new password
    match validate_password(new_password, Some(&user.username)) {
        Ok(_) => {},
        Err(PasswordValidationError::RequirementsNotMet(msg)) => {
            return Err(UserRegistrationError::PasswordValidationFailed(msg));
        },
        Err(PasswordValidationError::TooSimilarToUserInfo) => {
            return Err(UserRegistrationError::PasswordValidationFailed(
                "Password is too similar to username".to_string()
            ));
        },
        Err(e) => {
            return Err(UserRegistrationError::InternalError(e.to_string()));
        }
    }
    
    // Hash the new password
    let (password_hash, salt) = hash_password(new_password, 65536).map_err(|e| {
        UserRegistrationError::InternalError(format!("Failed to hash password: {}", e))
    })?;
    
    // Update the password in database
    let now = Utc::now();
    conn.execute(
        "UPDATE users SET 
            password_hash = ?1, 
            salt = ?2, 
            password_changed = ?3,
            updated_at = ?4,
            failed_login_attempts = 0,
            account_locked = 0,
            lockout_time = NULL
         WHERE id = ?5",
        params![
            password_hash,
            salt,
            now.to_rfc3339(),
            now.to_rfc3339(),
            user_id
        ]
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to update password: {}", e))
    })?;
    
    // Add audit log for password reset
    let audit_id = Uuid::new_v4().to_string();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_password_reset",
            user_id,
            "User password reset",
            now.to_rfc3339()
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for password reset: {}", e);
        // Continue even if audit log fails
        UserRegistrationError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    Ok(())
}

/// Get user by ID
fn get_user_by_id(conn: &Connection, user_id: &str) -> Result<Option<User>, rusqlite::Error> {
    let result = conn.query_row(
        "SELECT 
            id, username, password_hash, salt, role, 
            failed_login_attempts, account_locked, lockout_time,
            last_login, password_changed, totp_secret, totp_enabled,
            created_at, updated_at
         FROM users 
         WHERE id = ?1",
        params![user_id],
        |row| {
            let role_str: String = row.get(4)?;
            let role = UserRole::from_str(&role_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, 
                    rusqlite::types::Type::Text, Box::new(anyhow!(e))))?;
            
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?,
                role,
                failed_login_attempts: row.get(5)?,
                account_locked: row.get::<_, i32>(6)? != 0,
                lockout_time: row.get::<_, Option<String>>(7)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                last_login: row.get::<_, Option<String>>(8)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(8, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                password_changed: row.get::<_, Option<String>>(9)?
                    .map(|dt_str| chrono::DateTime::parse_from_rfc3339(&dt_str)
                         .map(|dt| dt.with_timezone(&Utc))
                         .map_err(|e| rusqlite::Error::FromSqlConversionFailure(9, 
                            rusqlite::types::Type::Text, Box::new(e))))
                    .transpose()?,
                totp_secret: row.get(10)?,
                totp_enabled: row.get::<_, i32>(11)? != 0,
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(12, 
                        rusqlite::types::Type::Text, Box::new(e)))?,
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(13)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(13, 
                        rusqlite::types::Type::Text, Box::new(e)))?,
            })
        }
    );
    
    match result {
        Ok(user) => Ok(Some(user)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Lock a user account after too many failed login attempts
pub fn lock_account(username: &str) -> Result<(), UserRegistrationError> {
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    let now = Utc::now();
    
    conn.execute(
        "UPDATE users SET 
            account_locked = 1, 
            lockout_time = ?1,
            updated_at = ?2
         WHERE username = ?3",
        params![
            now.to_rfc3339(),
            now.to_rfc3339(),
            username
        ]
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to lock account: {}", e))
    })?;
    
    // Get user ID for audit log
    let user_id = conn.query_row(
        "SELECT id FROM users WHERE username = ?1",
        params![username],
        |row| row.get::<_, String>(0)
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get user ID: {}", e))
    })?;
    
    // Add audit log for account locking
    let audit_id = Uuid::new_v4().to_string();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_locked",
            user_id,
            format!("User account locked: {}", username),
            now.to_rfc3339()
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for account locking: {}", e);
        // Continue even if audit log fails
        UserRegistrationError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    Ok(())
}

/// Unlock a user account
pub fn unlock_account(username: &str) -> Result<(), UserRegistrationError> {
    let conn = get_connection().map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    let now = Utc::now();
    
    conn.execute(
        "UPDATE users SET 
            account_locked = 0, 
            lockout_time = NULL,
            failed_login_attempts = 0,
            updated_at = ?1
         WHERE username = ?2",
        params![
            now.to_rfc3339(),
            username
        ]
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to unlock account: {}", e))
    })?;
    
    // Get user ID for audit log
    let user_id = conn.query_row(
        "SELECT id FROM users WHERE username = ?1",
        params![username],
        |row| row.get::<_, String>(0)
    ).map_err(|e| {
        UserRegistrationError::DatabaseError(format!("Failed to get user ID: {}", e))
    })?;
    
    // Add audit log for account unlocking
    let audit_id = Uuid::new_v4().to_string();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_unlocked",
            user_id,
            format!("User account unlocked: {}", username),
            now.to_rfc3339()
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for account unlocking: {}", e);
        // Continue even if audit log fails
        UserRegistrationError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_username_validation() {
        // Valid usernames
        assert!(is_valid_username("user123"));
        assert!(is_valid_username("john.doe"));
        assert!(is_valid_username("john_doe"));
        assert!(is_valid_username("john-doe"));
        
        // Invalid usernames
        assert!(!is_valid_username("ab")); // Too short
        assert!(!is_valid_username(".john")); // Starts with special character
        assert!(!is_valid_username("john.")); // Ends with special character
        assert!(!is_valid_username("john@doe")); // Contains invalid characters
        assert!(!is_valid_username(&"a".repeat(31))); // Too long
    }
} 