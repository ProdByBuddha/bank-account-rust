use anyhow::{Result, Context, anyhow};
use rusqlite::{Connection, params};
use log::{debug, info, warn, error};
use chrono::Utc;
use uuid::Uuid;
use serde::{Serialize, Deserialize};

use crate::database::{self, get_connection, encrypt_data, decrypt_data};
use crate::database::models::{User, UserRole};

/// User profile error types
#[derive(Debug, thiserror::Error)]
pub enum UserProfileError {
    #[error("User not found")]
    UserNotFound,
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// User profile model with sensitive information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub last_login: Option<String>,
    pub totp_enabled: bool,
    pub account_locked: bool,
    pub failed_login_attempts: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// User profile update fields
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserProfileUpdate {
    pub username: Option<String>,
    pub role: Option<UserRole>,
}

/// Get user profile by ID
pub fn get_user_profile(user_id: &str) -> Result<UserProfile, UserProfileError> {
    debug!("Getting user profile for ID: {}", user_id);
    
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Get user from database
    let result = conn.query_row(
        "SELECT 
            id, username, role, 
            last_login, totp_enabled, account_locked, 
            failed_login_attempts, created_at, updated_at
         FROM users 
         WHERE id = ?1",
        params![user_id],
        |row| {
            let role_str: String = row.get(2)?;
            let role = UserRole::from_str(&role_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, 
                    rusqlite::types::Type::Text, Box::new(anyhow!(e))))?;
            
            Ok(UserProfile {
                id: row.get(0)?,
                username: row.get(1)?,
                role,
                last_login: row.get::<_, Option<String>>(3)?,
                totp_enabled: row.get::<_, i32>(4)? != 0,
                account_locked: row.get::<_, i32>(5)? != 0,
                failed_login_attempts: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        }
    );
    
    match result {
        Ok(profile) => Ok(profile),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(UserProfileError::UserNotFound),
        Err(e) => Err(UserProfileError::DatabaseError(format!("Failed to get user: {}", e))),
    }
}

/// Update user profile
pub fn update_user_profile(
    user_id: &str,
    update: UserProfileUpdate,
    requesting_user_id: &str,
    requesting_user_role: &UserRole,
) -> Result<UserProfile, UserProfileError> {
    debug!("Updating user profile for ID: {}", user_id);
    
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Check if user exists
    let existing_user = conn.query_row(
        "SELECT id, role FROM users WHERE id = ?1",
        params![user_id],
        |row| {
            let role_str: String = row.get(1)?;
            let role = UserRole::from_str(&role_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, 
                    rusqlite::types::Type::Text, Box::new(anyhow!(e))))?;
            
            Ok((row.get::<_, String>(0)?, role))
        }
    );
    
    let (_, existing_role) = match existing_user {
        Ok(user) => user,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Err(UserProfileError::UserNotFound),
        Err(e) => return Err(UserProfileError::DatabaseError(format!("Failed to check user: {}", e))),
    };
    
    // Check authorization
    // User can update their own profile except role changes
    // Admin can update any profile including role changes
    if user_id != requesting_user_id {
        if *requesting_user_role != UserRole::Admin {
            return Err(UserProfileError::AuthorizationError(
                "Only admins can update other users' profiles".to_string()
            ));
        }
    } else if update.role.is_some() && *requesting_user_role != UserRole::Admin {
        return Err(UserProfileError::AuthorizationError(
            "Only admins can update roles".to_string()
        ));
    }
    
    // Build update query
    let mut update_query = String::from("UPDATE users SET updated_at = ?1");
    let now = Utc::now().to_rfc3339();
    let mut params_values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];
    let mut param_index = 2;
    
    if let Some(username) = &update.username {
        // Check if username is already taken (if changing)
        let result = conn.query_row(
            "SELECT 1 FROM users WHERE username = ?1 AND id != ?2",
            params![username, user_id],
            |_| Ok(true)
        );
        
        if let Ok(_) = result {
            return Err(UserProfileError::DatabaseError("Username already exists".to_string()));
        }
        
        update_query.push_str(&format!(", username = ?{}", param_index));
        params_values.push(Box::new(username.clone()));
        param_index += 1;
    }
    
    if let Some(role) = &update.role {
        update_query.push_str(&format!(", role = ?{}", param_index));
        params_values.push(Box::new(role.as_str()));
        param_index += 1;
    }
    
    // Finalize query
    update_query.push_str(" WHERE id = ?");
    params_values.push(Box::new(user_id));
    
    // Execute update
    conn.execute(
        &update_query,
        rusqlite::params_from_iter(params_values.iter().map(|p| p.as_ref())),
    ).map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to update user: {}", e))
    })?;
    
    // Add audit log for profile update
    let audit_id = Uuid::new_v4().to_string();
    
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5
        )",
        params![
            audit_id,
            "user_updated",
            user_id,
            format!("User profile updated by user {}", requesting_user_id),
            now
        ]
    ).map_err(|e| {
        warn!("Failed to create audit log for profile update: {}", e);
        // Continue even if audit log fails
        UserProfileError::DatabaseError(format!("Failed to create audit log: {}", e))
    })?;
    
    // Return updated profile
    get_user_profile(user_id)
}

/// List all users (for admin)
pub fn list_users(
    requesting_user_role: &UserRole,
    limit: usize,
    offset: usize
) -> Result<Vec<UserProfile>, UserProfileError> {
    // Check authorization
    if *requesting_user_role != UserRole::Admin {
        return Err(UserProfileError::AuthorizationError(
            "Only admins can list all users".to_string()
        ));
    }
    
    // Get database connection
    let conn = get_connection().map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to get database connection: {}", e))
    })?;
    
    // Get users from database
    let mut stmt = conn.prepare(
        "SELECT 
            id, username, role, 
            last_login, totp_enabled, account_locked, 
            failed_login_attempts, created_at, updated_at
         FROM users 
         ORDER BY username
         LIMIT ?1 OFFSET ?2"
    ).map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to prepare query: {}", e))
    })?;
    
    let user_iter = stmt.query_map(params![limit as i64, offset as i64], |row| {
        let role_str: String = row.get(2)?;
        let role = UserRole::from_str(&role_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, 
                rusqlite::types::Type::Text, Box::new(anyhow!(e))))?;
        
        Ok(UserProfile {
            id: row.get(0)?,
            username: row.get(1)?,
            role,
            last_login: row.get::<_, Option<String>>(3)?,
            totp_enabled: row.get::<_, i32>(4)? != 0,
            account_locked: row.get::<_, i32>(5)? != 0,
            failed_login_attempts: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    }).map_err(|e| {
        UserProfileError::DatabaseError(format!("Failed to query users: {}", e))
    })?;
    
    let mut users = Vec::new();
    for user in user_iter {
        users.push(user.map_err(|e| {
            UserProfileError::DatabaseError(format!("Failed to read user: {}", e))
        })?);
    }
    
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::models::UserRole;
    
    // These tests would require setting up a test database
    // with proper fixtures. For now, we'll just have a skeleton
    // to be filled in later.
    
    #[test]
    #[ignore]
    fn test_get_user_profile() {
        // Test would set up a user and retrieve their profile
    }
    
    #[test]
    #[ignore]
    fn test_update_user_profile() {
        // Test would set up a user and update their profile
    }
    
    #[test]
    #[ignore]
    fn test_list_users() {
        // Test would set up multiple users and list them
    }
} 