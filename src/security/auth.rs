use anyhow::{Result, Context, anyhow};
use chrono::{DateTime, Duration, Utc};
use log::{debug, warn, error};
use rusqlite::Connection;
use std::fmt;

use crate::database::models::UserRole;
use crate::security::jwt::{self, validate_token_with_db, Claims};

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
    /// The user's role
    pub role: UserRole,
    /// Whether two-factor authentication has been verified
    pub tfa_verified: bool,
    /// The JWT token ID
    pub token_id: String,
    /// The token's last activity time
    pub last_activity: DateTime<Utc>,
}

impl AuthResult {
    /// Create a new AuthResult from JWT claims
    fn from_claims(claims: Claims) -> Result<Self> {
        let role = UserRole::from_str(&claims.role)
            .map_err(|e| anyhow!("Invalid role in token: {}", e))?;
        
        Ok(Self {
            user_id: claims.sub,
            username: claims.username,
            role,
            tfa_verified: claims.tfa_verified,
            token_id: claims.jti,
            last_activity: Utc::now(),
        })
    }
    
    /// Check if the user has a particular role
    pub fn has_role(&self, role: &UserRole) -> bool {
        &self.role == role
    }
    
    /// Check if the user is an admin
    pub fn is_admin(&self) -> bool {
        self.role == UserRole::Admin
    }
    
    /// Check if the user has completed two-factor authentication
    pub fn has_verified_tfa(&self) -> bool {
        self.tfa_verified
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
    if !auth_result.has_role(required_role) && !auth_result.is_admin() {
        // Admin can do anything, otherwise check specific role
        return Err(AuthError::InsufficientPermissions);
    }
    
    Ok(())
}

/// Check if two-factor authentication is verified
pub fn require_tfa(auth_result: &AuthResult) -> Result<(), AuthError> {
    if !auth_result.has_verified_tfa() {
        return Err(AuthError::TwoFactorRequired);
    }
    
    Ok(())
}

/// Check for session timeout based on last activity
pub fn check_session_timeout(
    last_activity: &DateTime<Utc>,
    config: &SessionTimeoutConfig,
) -> Result<(), AuthError> {
    if !config.enforce {
        return Ok(());
    }
    
    let now = Utc::now();
    let timeout_duration = Duration::minutes(config.max_inactivity_minutes as i64);
    
    if now - *last_activity > timeout_duration {
        return Err(AuthError::SessionTimeout);
    }
    
    Ok(())
}

/// Refresh a user's token when it's about to expire
pub fn refresh_if_needed(
    conn: &Connection,
    token: &str,
    refresh_token: &str,
    refresh_threshold_minutes: i64,
) -> Result<Option<String>, AuthError> {
    // Validate the token without checking revocation yet
    let claims = match jwt::validate_token(token) {
        Ok(claims) => claims,
        Err(err) => {
            return Err(AuthError::InvalidToken(err.to_string()));
        }
    };
    
    // Check if token is close to expiry
    let now = Utc::now();
    let expires_at = DateTime::from_timestamp(claims.exp, 0)
        .ok_or_else(|| AuthError::InvalidToken("Invalid expiration time".to_string()))?;
    
    let time_until_expiry = expires_at - now;
    
    // If token is about to expire, refresh it
    if time_until_expiry < Duration::minutes(refresh_threshold_minutes) {
        debug!("Token is about to expire, refreshing");
        
        match jwt::refresh_access_token(conn, refresh_token) {
            Ok(new_token) => Ok(Some(new_token)),
            Err(err) => {
                Err(AuthError::InvalidToken(format!("Failed to refresh token: {}", err)))
            }
        }
    } else {
        // Token is still valid and not close to expiry
        Ok(None)
    }
}

/// Logout a user by revoking their token
pub fn logout(conn: &Connection, token_id: &str) -> Result<(), AuthError> {
    match jwt::revoke_token(conn, token_id) {
        Ok(_) => {
            debug!("Token {} revoked successfully", token_id);
            Ok(())
        }
        Err(err) => {
            error!("Failed to revoke token {}: {}", token_id, err);
            Err(AuthError::DatabaseError(err.to_string()))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::jwt::{generate_token, TokenType};
    use tempfile::TempDir;
    
    // Helper to set up a test database
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        
        // Create tokens table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                device_info TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL,
                revoked_at TEXT
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
            role: "user".to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            jti: "token123".to_string(),
            iss: "test_issuer".to_string(),
            tfa_verified: true,
            refresh: None,
        };
        
        let auth_result = AuthResult::from_claims(claims).unwrap();
        
        assert_eq!(auth_result.user_id, "user123");
        assert_eq!(auth_result.username, "testuser");
        assert_eq!(auth_result.role, UserRole::User);
        assert_eq!(auth_result.tfa_verified, true);
        assert_eq!(auth_result.token_id, "token123");
    }
    
    #[test]
    fn test_require_role() {
        let auth_result = AuthResult {
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token123".to_string(),
            last_activity: Utc::now(),
        };
        
        // Same role should succeed
        assert!(require_role(&auth_result, &UserRole::User).is_ok());
        
        // Admin role should fail
        assert!(require_role(&auth_result, &UserRole::Admin).is_err());
        
        // Test with admin user
        let admin_result = AuthResult {
            user_id: "admin123".to_string(),
            username: "adminuser".to_string(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token456".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin can access user role
        assert!(require_role(&admin_result, &UserRole::User).is_ok());
        
        // Admin can access admin role
        assert!(require_role(&admin_result, &UserRole::Admin).is_ok());
    }
    
    #[test]
    fn test_session_timeout() {
        let now = Utc::now();
        let config = SessionTimeoutConfig {
            max_inactivity_minutes: 30,
            enforce: true,
        };
        
        // Recent activity should be fine
        let recent_activity = now - Duration::minutes(20);
        assert!(check_session_timeout(&recent_activity, &config).is_ok());
        
        // Old activity should timeout
        let old_activity = now - Duration::minutes(40);
        assert!(check_session_timeout(&old_activity, &config).is_err());
        
        // Disabled timeout enforcement should always pass
        let disabled_config = SessionTimeoutConfig {
            max_inactivity_minutes: 30,
            enforce: false,
        };
        assert!(check_session_timeout(&old_activity, &disabled_config).is_ok());
    }
} 