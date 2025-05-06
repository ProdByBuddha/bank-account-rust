use anyhow::{Result, Context, anyhow};
use chrono::{DateTime, Duration, Utc};
use log::{debug, warn, error};
use rusqlite::Connection;
use std::fmt;

use crate::database::models::UserRole;
use crate::security::jwt::{self, validate_token_with_db, Claims};
use crate::security::roles::{Permission, RbacError, has_permission};

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    /// Token is missing
    MissingToken,
    /// Token is invalid (malformed, expired, etc.)
    InvalidToken(String),
    /// Token has been revoked
    RevokedToken,
    /// User lacks required permissions
    InsufficientPermissions,
    /// Two-factor authentication required
    TwoFactorRequired,
    /// Session has timed out due to inactivity
    SessionTimeout,
    /// Database error
    DatabaseError(String),
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::MissingToken => write!(f, "Authentication token is missing"),
            AuthError::InvalidToken(err) => write!(f, "Authentication token is invalid: {}", err),
            AuthError::RevokedToken => write!(f, "Authentication token has been revoked"),
            AuthError::InsufficientPermissions => write!(f, "User lacks required permissions"),
            AuthError::TwoFactorRequired => write!(f, "Two-factor authentication is required"),
            AuthError::SessionTimeout => write!(f, "Session has timed out due to inactivity"),
            AuthError::DatabaseError(err) => write!(f, "Database error: {}", err),
            AuthError::Unknown(err) => write!(f, "Unknown authentication error: {}", err),
        }
    }
}

impl std::error::Error for AuthError {}

/// Result of the authentication process
pub struct AuthResult {
    /// The authenticated user ID
    pub user_id: String,
    /// The username
    pub username: String,
    /// Whether the user is an admin
    pub is_admin: bool,
    /// The token for authentication purposes
    pub token: String,
}

impl AuthResult {
    /// Create a new AuthResult from JWT claims
    fn from_claims(claims: Claims) -> Result<Self> {
        let role = UserRole::from_str(&claims.role)
            .map_err(|e| anyhow!("Invalid role in token: {}", e))?;
        
        Ok(Self {
            user_id: claims.sub,
            username: claims.username,
            is_admin: role == UserRole::Admin,
            token: claims.jti,
        })
    }
    
    /// Check if the user has a specific permission by name
    pub fn has_permission(&self, permission_name: &str) -> bool {
        // Admins have all permissions
        if self.is_admin {
            return true;
        }
        
        // For non-admins, check the specific permission
        match permission_name {
            // Backup permissions - only admins have these by default
            "backup_create" | "backup_restore" | "backup_list" | 
            "backup_verify" | "backup_delete" | "backup_schedule" => false,
            
            // Default user permissions
            "view_account" | "deposit" | "withdraw" | 
            "transfer" | "view_transactions" => true,
            
            // All other permissions require admin
            _ => false,
        }
    }
    
    /// Create a new AuthResult for testing purposes
    #[cfg(test)]
    pub fn for_test(
        user_id: &str,
        username: &str,
        is_admin: bool,
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            username: username.to_string(),
            is_admin,
            token: "test_token".to_string(),
        }
    }
}

/// Session timeout configuration
pub struct SessionTimeoutConfig {
    /// Maximum inactivity time in minutes
    pub max_inactivity_minutes: u64,
    /// Whether to enforce session timeout
    pub enforce: bool,
}

impl Default for SessionTimeoutConfig {
    fn default() -> Self {
        Self {
            max_inactivity_minutes: 30, // Default to 30 minutes
            enforce: true,
        }
    }
}

/// Authenticate a request using a JWT token
pub fn authenticate(conn: &Connection, token: &str) -> Result<AuthResult, AuthError> {
    if token.is_empty() {
        return Err(AuthError::MissingToken);
    }
    
    // Validate the token and check for revocation
    let claims = match validate_token_with_db(conn, token) {
        Ok(claims) => claims,
        Err(err) => {
            let error_msg = err.to_string();
            
            if error_msg.contains("revoked") {
                return Err(AuthError::RevokedToken);
            } else if error_msg.contains("expired") || error_msg.contains("invalid") {
                return Err(AuthError::InvalidToken(error_msg));
            } else {
                return Err(AuthError::Unknown(error_msg));
            }
        }
    };
    
    // Create auth result from claims
    let auth_result = AuthResult::from_claims(claims).map_err(|e| {
        AuthError::InvalidToken(format!("Failed to process claims: {}", e))
    })?;
    
    Ok(auth_result)
}

/// Check if a user has the required role
pub fn require_role(
    auth_result: &AuthResult,
    required_role: &UserRole,
) -> Result<(), AuthError> {
    if !auth_result.is_admin && required_role == &UserRole::Admin {
        // Only admins can perform admin actions
        return Err(AuthError::InsufficientPermissions);
    }
    
    Ok(())
}

/// Check if a user has the required permission
pub fn require_permission(
    conn: &Connection,
    auth_result: &AuthResult,
    permission: Permission,
) -> Result<(), AuthError> {
    // In a real implementation, we would check if the user has the specific permission
    // For now, we'll just check if they're an admin
    if !auth_result.is_admin && permission.requires_admin() {
        return Err(AuthError::InsufficientPermissions);
    }
    
    Ok(())
}

/// Logout a user by revoking their token
pub fn logout(conn: &Connection, auth_result: &AuthResult) -> Result<(), AuthError> {
    // Revoke the token in the database
    match jwt::revoke_token(conn, &auth_result.token) {
        Ok(_) => Ok(()),
        Err(e) => Err(AuthError::Unknown(e.to_string())),
    }
}

/// Revoke all tokens for a user (logout from all devices)
pub fn logout_all_devices(conn: &Connection, user_id: &str) -> Result<usize, AuthError> {
    match jwt::revoke_all_user_tokens(conn, user_id) {
        Ok(count) => {
            debug!("Revoked {} tokens for user {}", count, user_id);
            Ok(count)
        }
        Err(err) => {
            error!("Failed to revoke all tokens for user {}: {}", user_id, err);
            Err(AuthError::DatabaseError(err.to_string()))
        }
    }
}

// Implement conversion from RbacError to AuthError
impl From<RbacError> for AuthError {
    fn from(error: RbacError) -> Self {
        match error {
            RbacError::InsufficientPermission(_) => AuthError::InsufficientPermissions,
            RbacError::DatabaseError(msg) => AuthError::DatabaseError(msg),
            RbacError::RoleUpdateError(msg) => AuthError::Unknown(format!("Role update error: {}", msg)),
            RbacError::PermissionUpdateError(msg) => AuthError::Unknown(format!("Permission update error: {}", msg)),
            RbacError::InvalidOperation(msg) => AuthError::Unknown(format!("Invalid operation: {}", msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = Connection::open(&db_path).unwrap();
        
        // Create a simple schema for testing
        conn.execute(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL
            )",
            [],
        ).unwrap();
        
        conn.execute(
            "CREATE TABLE tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )",
            [],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_auth_result_from_claims() {
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: "admin".to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            jti: "token123".to_string(),
            iss: "test".to_string(),
            tfa_verified: true,
            refresh: None,
        };
        
        let auth_result = AuthResult::from_claims(claims).unwrap();
        
        assert_eq!(auth_result.user_id, "user123");
        assert_eq!(auth_result.username, "testuser");
        assert_eq!(auth_result.role, UserRole::Admin);
        assert_eq!(auth_result.token_id, "token123");
        assert!(auth_result.tfa_verified);
    }
    
    #[test]
    fn test_require_role() {
        let admin_auth = AuthResult {
            user_id: "user123".to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token123".to_string(),
            last_activity: Utc::now(),
        };
        
        let user_auth = AuthResult {
            user_id: "user456".to_string(),
            username: "user".to_string(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token456".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin can access admin routes
        assert!(require_role(&admin_auth, &UserRole::Admin).is_ok());
        
        // Admin can access user routes
        assert!(require_role(&admin_auth, &UserRole::User).is_ok());
        
        // User can access user routes
        assert!(require_role(&user_auth, &UserRole::User).is_ok());
        
        // User cannot access admin routes
        assert!(require_role(&user_auth, &UserRole::Admin).is_err());
    }
    
    #[test]
    fn test_session_timeout() {
        let config = SessionTimeoutConfig {
            max_inactivity_minutes: 30,
            enforce: true,
        };
        
        let current_time = Utc::now();
        let recent_activity = current_time - Duration::minutes(10);
        let old_activity = current_time - Duration::minutes(60);
        
        // Recent activity should not time out
        assert!(check_session_timeout(&recent_activity, &config).is_ok());
        
        // Old activity should time out
        assert!(check_session_timeout(&old_activity, &config).is_err());
        
        // If timeout is not enforced, even old activity should be ok
        let no_enforce_config = SessionTimeoutConfig {
            max_inactivity_minutes: 30,
            enforce: false,
        };
        assert!(check_session_timeout(&old_activity, &no_enforce_config).is_ok());
    }
} 