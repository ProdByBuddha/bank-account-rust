use anyhow::{Result, Context, anyhow};
use log::{debug, info, error};
use rusqlite::Connection;
use std::io::{self, Write};

use crate::database;
use crate::database::models::{User, UserRole};
use crate::security::auth::AuthResult;
use crate::security::roles::{self, Permission, RbacError};
use crate::cli::utils::read_line;

/// List all users with their roles
pub fn list_users(auth: &AuthResult) -> Result<()> {
    // Check if the user has permission to view users
    roles::require_permission(auth, Permission::ViewUsers)
        .map_err(|e| anyhow!("Permission error: {}", e))?;
    
    let conn = database::get_connection()?;
    
    // Query users from the database
    let mut stmt = conn.prepare(
        "SELECT id, username, role FROM users ORDER BY username"
    )?;
    
    let users = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    
    // Print the users and their roles
    println!("{:<36} {:<30} {:<10}", "ID", "Username", "Role");
    println!("{:-<36} {:-<30} {:-<10}", "", "", "");
    
    for user in users {
        if let Ok((id, username, role)) = user {
            println!("{:<36} {:<30} {:<10}", id, username, role);
        }
    }
    
    Ok(())
}

/// Change a user's role
pub fn change_user_role(auth: &AuthResult, user_id: &str, new_role_str: &str) -> Result<()> {
    // Parse the new role
    let new_role = match new_role_str.to_lowercase().as_str() {
        "admin" => UserRole::Admin,
        "user" => UserRole::User,
        _ => return Err(anyhow!("Invalid role: {}. Valid roles are 'admin' or 'user'", new_role_str)),
    };
    
    // Get database connection
    let conn = database::get_connection()?;
    
    // Check if the user exists
    let user_exists = conn.query_row(
        "SELECT 1 FROM users WHERE id = ?",
        [user_id],
        |_| Ok(true)
    ).optional()?.unwrap_or(false);
    
    if !user_exists {
        return Err(anyhow!("User with ID {} does not exist", user_id));
    }
    
    // Get the current role for confirmation
    let current_role: String = conn.query_row(
        "SELECT role FROM users WHERE id = ?",
        [user_id],
        |row| row.get(0)
    )?;
    
    // Get the username for display
    let username: String = conn.query_row(
        "SELECT username FROM users WHERE id = ?",
        [user_id],
        |row| row.get(0)
    )?;
    
    println!("Current role for user '{}': {}", username, current_role);
    println!("New role will be: {}", new_role.as_str());
    
    // Confirm the change
    print!("Are you sure you want to change this user's role? (y/n): ");
    io::stdout().flush()?;
    
    let confirm = read_line("")?.to_lowercase();
    if confirm != "y" && confirm != "yes" {
        println!("Operation cancelled.");
        return Ok(());
    }
    
    // Attempt to change the role
    match roles::change_user_role(&conn, auth, user_id, new_role.clone()) {
        Ok(()) => {
            println!("✅ Successfully changed role for user '{}' to {}", username, new_role.as_str());
            Ok(())
        },
        Err(RbacError::InsufficientPermission(_)) => {
            println!("❌ You do not have permission to change user roles.");
            Err(anyhow!("Insufficient permissions"))
        },
        Err(RbacError::InvalidOperation(msg)) => {
            println!("❌ Cannot change role: {}", msg);
            Err(anyhow!("Invalid operation: {}", msg))
        },
        Err(e) => {
            println!("❌ Failed to change user role: {}", e);
            Err(anyhow!("Failed to change user role: {}", e))
        }
    }
}

/// List available permissions for each role
pub fn list_permissions() -> Result<()> {
    let permissions = roles::get_default_permissions();
    
    for (role, perms) in &permissions {
        println!("Role: {}", role.as_str());
        println!("{:-<50}", "");
        
        for perm in perms {
            println!("  • {}", perm.as_str());
        }
        
        println!();
    }
    
    Ok(())
}

/// Check if a user has a specific permission
pub fn check_permission(auth: &AuthResult, permission_str: &str) -> Result<()> {
    // Parse the permission
    let permission = match Permission::from_str(permission_str) {
        Ok(p) => p,
        Err(e) => return Err(anyhow!("Invalid permission: {}", e)),
    };
    
    // Check if the user has the permission
    if roles::has_permission(auth, permission) {
        println!("✅ User '{}' has permission: {}", auth.username, permission_str);
    } else {
        println!("❌ User '{}' does not have permission: {}", auth.username, permission_str);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::database::schema;
    use crate::database::models::User;
    use uuid::Uuid;
    use crate::security::password;
    use chrono::Utc;
    
    // Helper to set up a test database
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = Connection::open(&db_path).unwrap();
        
        // Create schema
        schema::create_schema(&mut conn.clone()).unwrap();
        
        (conn, temp_dir)
    }
    
    // Helper to create a test user
    fn create_test_user(conn: &Connection, username: &str, role: UserRole) -> User {
        let user_id = Uuid::new_v4().to_string();
        let password = "Test_password123!";
        let (password_hash, salt) = password::hash_password(password).unwrap();
        
        let user = User::new(username.to_string(), password_hash, salt, role.clone());
        
        // Insert user into database
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, failed_login_attempts, 
            account_locked, created_at, updated_at) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.salt,
                user.role.as_str(),
                user.failed_login_attempts,
                user.account_locked as i32,
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
            ],
        ).unwrap();
        
        user
    }
    
    #[test]
    fn test_check_permission() {
        // Create an admin auth result
        let admin_auth = AuthResult {
            user_id: "admin_id".to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin should have all permissions
        assert!(check_permission(&admin_auth, "create_user").is_ok());
        assert!(check_permission(&admin_auth, "view_users").is_ok());
        
        // Create a regular user auth result
        let user_auth = AuthResult {
            user_id: "user_id".to_string(),
            username: "user".to_string(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Regular user should have limited permissions
        assert!(check_permission(&user_auth, "deposit").is_ok());
        assert!(check_permission(&user_auth, "withdraw").is_ok());
        
        // Invalid permission should return an error
        assert!(check_permission(&admin_auth, "invalid_permission").is_err());
    }
} 