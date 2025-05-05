use anyhow::{Result, Context, anyhow};
use chrono::Utc;
use log::{debug, warn, info};
use rusqlite::Connection;
use std::collections::HashMap;
use std::fmt;

use crate::database::models::{User, UserRole};
use crate::security::auth::AuthResult;
use crate::database;

/// Permission type for role-based access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // User management permissions
    CreateUser,
    ViewUsers,
    UpdateUser,
    DeleteUser,
    
    // Account management permissions
    CreateAccount,
    ViewAccount,
    UpdateAccount,
    CloseAccount,
    
    // Transaction permissions
    Deposit,
    Withdraw,
    Transfer,
    ViewTransactions,
    
    // Administrative permissions
    ManageRoles,
    ViewAuditLogs,
    ConfigureSystem,
    RunComplianceChecks,
    
    // Backup and restore permissions
    BackupCreate,
    BackupRestore,
    BackupList,
    BackupVerify,
    BackupDelete,
    BackupSchedule,
}

impl Permission {
    /// Convert permission to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::CreateUser => "create_user",
            Permission::ViewUsers => "view_users",
            Permission::UpdateUser => "update_user",
            Permission::DeleteUser => "delete_user",
            
            Permission::CreateAccount => "create_account",
            Permission::ViewAccount => "view_account",
            Permission::UpdateAccount => "update_account",
            Permission::CloseAccount => "close_account",
            
            Permission::Deposit => "deposit",
            Permission::Withdraw => "withdraw",
            Permission::Transfer => "transfer",
            Permission::ViewTransactions => "view_transactions",
            
            Permission::ManageRoles => "manage_roles",
            Permission::ViewAuditLogs => "view_audit_logs",
            Permission::ConfigureSystem => "configure_system",
            Permission::RunComplianceChecks => "run_compliance_checks",
            
            Permission::BackupCreate => "backup_create",
            Permission::BackupRestore => "backup_restore",
            Permission::BackupList => "backup_list",
            Permission::BackupVerify => "backup_verify",
            Permission::BackupDelete => "backup_delete",
            Permission::BackupSchedule => "backup_schedule",
        }
    }
    
    /// Parse permission from string
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "create_user" => Ok(Permission::CreateUser),
            "view_users" => Ok(Permission::ViewUsers),
            "update_user" => Ok(Permission::UpdateUser),
            "delete_user" => Ok(Permission::DeleteUser),
            
            "create_account" => Ok(Permission::CreateAccount),
            "view_account" => Ok(Permission::ViewAccount),
            "update_account" => Ok(Permission::UpdateAccount),
            "close_account" => Ok(Permission::CloseAccount),
            
            "deposit" => Ok(Permission::Deposit),
            "withdraw" => Ok(Permission::Withdraw),
            "transfer" => Ok(Permission::Transfer),
            "view_transactions" => Ok(Permission::ViewTransactions),
            
            "manage_roles" => Ok(Permission::ManageRoles),
            "view_audit_logs" => Ok(Permission::ViewAuditLogs),
            "configure_system" => Ok(Permission::ConfigureSystem),
            "run_compliance_checks" => Ok(Permission::RunComplianceChecks),
            
            "backup_create" => Ok(Permission::BackupCreate),
            "backup_restore" => Ok(Permission::BackupRestore),
            "backup_list" => Ok(Permission::BackupList),
            "backup_verify" => Ok(Permission::BackupVerify),
            "backup_delete" => Ok(Permission::BackupDelete),
            "backup_schedule" => Ok(Permission::BackupSchedule),
            
            // Legacy permission mapping for backward compatibility
            "backup_restore" => Ok(Permission::BackupRestore),
            
            _ => Err(format!("Unknown permission: {}", s)),
        }
    }
}

/// Role-based access control error
#[derive(Debug)]
pub enum RbacError {
    /// User lacks required permission
    InsufficientPermission(Permission),
    /// Error updating role
    RoleUpdateError(String),
    /// Error updating permissions
    PermissionUpdateError(String),
    /// Database error
    DatabaseError(String),
    /// Invalid operation (e.g., removing admin role from the last admin)
    InvalidOperation(String),
}

impl fmt::Display for RbacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RbacError::InsufficientPermission(perm) => 
                write!(f, "Insufficient permission: {}", perm.as_str()),
            RbacError::RoleUpdateError(msg) => 
                write!(f, "Role update error: {}", msg),
            RbacError::PermissionUpdateError(msg) => 
                write!(f, "Permission update error: {}", msg),
            RbacError::DatabaseError(msg) => 
                write!(f, "Database error: {}", msg),
            RbacError::InvalidOperation(msg) => 
                write!(f, "Invalid operation: {}", msg),
        }
    }
}

impl std::error::Error for RbacError {}

/// Get default permissions for each role
pub fn get_default_permissions() -> HashMap<UserRole, Vec<Permission>> {
    let mut permissions = HashMap::new();
    
    // Regular user permissions
    permissions.insert(UserRole::User, vec![
        Permission::ViewAccount,
        Permission::Deposit,
        Permission::Withdraw,
        Permission::Transfer,
        Permission::ViewTransactions,
    ]);
    
    // Admin permissions (has all permissions)
    permissions.insert(UserRole::Admin, vec![
        // User management
        Permission::CreateUser,
        Permission::ViewUsers,
        Permission::UpdateUser,
        Permission::DeleteUser,
        
        // Account management
        Permission::CreateAccount,
        Permission::ViewAccount,
        Permission::UpdateAccount,
        Permission::CloseAccount,
        
        // Transaction permissions
        Permission::Deposit,
        Permission::Withdraw,
        Permission::Transfer,
        Permission::ViewTransactions,
        
        // Administrative permissions
        Permission::ManageRoles,
        Permission::ViewAuditLogs,
        Permission::ConfigureSystem,
        Permission::RunComplianceChecks,
        
        // Backup and restore permissions
        Permission::BackupCreate,
        Permission::BackupRestore,
        Permission::BackupList,
        Permission::BackupVerify,
        Permission::BackupDelete,
        Permission::BackupSchedule,
    ]);
    
    permissions
}

/// Check if a user has a specific permission
pub fn has_permission(auth: &AuthResult, permission: Permission) -> bool {
    // Admins have all permissions
    if auth.is_admin() {
        return true;
    }
    
    // Check user-specific permissions
    let default_permissions = get_default_permissions();
    if let Some(role_permissions) = default_permissions.get(&auth.role) {
        role_permissions.contains(&permission)
    } else {
        false
    }
}

/// Require a specific permission or return error
pub fn require_permission(auth: &AuthResult, permission: Permission) -> Result<(), RbacError> {
    if !has_permission(auth, permission) {
        Err(RbacError::InsufficientPermission(permission))
    } else {
        Ok(())
    }
}

/// Change a user's role
pub fn change_user_role(
    conn: &Connection,
    requester: &AuthResult,
    user_id: &str,
    new_role: UserRole,
) -> Result<(), RbacError> {
    // Check if requester has permission to manage roles
    require_permission(requester, Permission::ManageRoles)?;
    
    // Prevent changing own role (security measure)
    if requester.user_id == user_id {
        return Err(RbacError::InvalidOperation("Cannot change your own role".to_string()));
    }
    
    // If demoting from admin to regular user, make sure there's at least one admin left
    if new_role != UserRole::Admin {
        // Check if target user is currently an admin
        let query = "SELECT role FROM users WHERE id = ?";
        let current_role: String = conn.query_row(query, [user_id], |row| row.get(0))
            .map_err(|e| RbacError::DatabaseError(format!("Failed to get user role: {}", e)))?;
        
        if current_role == "admin" {
            // Count remaining admins
            let query = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?";
            let admin_count: i64 = conn.query_row(query, [user_id], |row| row.get(0))
                .map_err(|e| RbacError::DatabaseError(format!("Failed to count admins: {}", e)))?;
            
            if admin_count == 0 {
                return Err(RbacError::InvalidOperation(
                    "Cannot remove the last admin account".to_string()
                ));
            }
        }
    }
    
    // Update the user's role
    let query = "UPDATE users SET role = ?, updated_at = ? WHERE id = ?";
    let now = Utc::now().to_rfc3339();
    
    match conn.execute(query, [new_role.as_str(), &now, user_id]) {
        Ok(rows) if rows == 1 => {
            // Add audit log
            let details = format!(
                "Role changed to {} for user {}", 
                new_role.as_str(), 
                user_id
            );
            
            database::add_audit_log(
                conn,
                "role_changed",
                Some(&requester.user_id),
                Some(&details),
            )
            .map_err(|e| RbacError::DatabaseError(format!("Failed to add audit log: {}", e)))?;
            
            debug!("Changed role to {} for user {}", new_role.as_str(), user_id);
            Ok(())
        },
        Ok(_) => Err(RbacError::RoleUpdateError("User not found".to_string())),
        Err(e) => Err(RbacError::DatabaseError(format!("Database error: {}", e))),
    }
}

/// Check if user is the last admin
pub fn is_last_admin(conn: &Connection, user_id: &str) -> Result<bool, RbacError> {
    // Get current user role
    let query = "SELECT role FROM users WHERE id = ?";
    let role: String = conn.query_row(query, [user_id], |row| row.get(0))
        .map_err(|e| RbacError::DatabaseError(format!("Failed to get user role: {}", e)))?;
    
    // If not admin, return false
    if role != "admin" {
        return Ok(false);
    }
    
    // Count remaining admins
    let query = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?";
    let admin_count: i64 = conn.query_row(query, [user_id], |row| row.get(0))
        .map_err(|e| RbacError::DatabaseError(format!("Failed to count admins: {}", e)))?;
    
    Ok(admin_count == 0)
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use uuid::Uuid;
    use crate::database::schema;
    use crate::security::password;
    
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
    fn create_test_user(conn: &Connection, role: UserRole) -> User {
        let user_id = Uuid::new_v4().to_string();
        let username = format!("test_user_{}", user_id.split('-').next().unwrap());
        let password = "Test_password123!";
        let (password_hash, salt) = password::hash_password(password).unwrap();
        
        let user = User::new(username.clone(), password_hash, salt, role.clone());
        
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
    fn test_permission_conversion() {
        let permission = Permission::CreateUser;
        let permission_str = permission.as_str();
        
        assert_eq!(permission_str, "create_user");
        assert_eq!(Permission::from_str(permission_str).unwrap(), permission);
        
        // Test invalid permission
        assert!(Permission::from_str("invalid_permission").is_err());
    }
    
    #[test]
    fn test_has_permission() {
        // Create an admin auth result
        let admin_auth = AuthResult {
            user_id: "admin_id".to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Create a regular user auth result
        let user_auth = AuthResult {
            user_id: "user_id".to_string(),
            username: "user".to_string(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin should have all permissions
        assert!(has_permission(&admin_auth, Permission::CreateUser));
        assert!(has_permission(&admin_auth, Permission::ManageRoles));
        assert!(has_permission(&admin_auth, Permission::ViewAccount));
        
        // Regular user should have limited permissions
        assert!(!has_permission(&user_auth, Permission::CreateUser));
        assert!(!has_permission(&user_auth, Permission::ManageRoles));
        assert!(has_permission(&user_auth, Permission::ViewAccount));
        assert!(has_permission(&user_auth, Permission::Deposit));
    }
    
    #[test]
    fn test_require_permission() {
        // Create an admin auth result
        let admin_auth = AuthResult {
            user_id: "admin_id".to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Create a regular user auth result
        let user_auth = AuthResult {
            user_id: "user_id".to_string(),
            username: "user".to_string(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin should pass all permission checks
        assert!(require_permission(&admin_auth, Permission::CreateUser).is_ok());
        
        // Regular user should fail on admin permissions
        assert!(require_permission(&user_auth, Permission::CreateUser).is_err());
        
        // But pass on user permissions
        assert!(require_permission(&user_auth, Permission::ViewAccount).is_ok());
    }
    
    #[test]
    fn test_change_user_role() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create an admin user
        let admin_user = create_test_user(&conn, UserRole::Admin);
        
        // Create a regular user
        let regular_user = create_test_user(&conn, UserRole::User);
        
        // Create auth result for admin
        let admin_auth = AuthResult {
            user_id: admin_user.id.clone(),
            username: admin_user.username.clone(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Admin should be able to promote a regular user to admin
        assert!(change_user_role(&conn, &admin_auth, &regular_user.id, UserRole::Admin).is_ok());
        
        // Verify the role was changed
        let query = "SELECT role FROM users WHERE id = ?";
        let new_role: String = conn.query_row(query, [&regular_user.id], |row| row.get(0)).unwrap();
        assert_eq!(new_role, "admin");
        
        // Create a second admin auth result
        let admin2_auth = AuthResult {
            user_id: regular_user.id.clone(),
            username: regular_user.username.clone(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // The second admin should be able to demote the first admin
        assert!(change_user_role(&conn, &admin2_auth, &admin_user.id, UserRole::User).is_ok());
        
        // Verify the role was changed
        let query = "SELECT role FROM users WHERE id = ?";
        let new_role: String = conn.query_row(query, [&admin_user.id], |row| row.get(0)).unwrap();
        assert_eq!(new_role, "user");
        
        // But shouldn't be able to demote themselves
        assert!(change_user_role(&conn, &admin2_auth, &regular_user.id, UserRole::User).is_err());
        
        // And if we try to demote the last admin, it should fail
        let user3 = create_test_user(&conn, UserRole::User);
        let user3_auth = AuthResult {
            user_id: user3.id.clone(),
            username: user3.username.clone(),
            role: UserRole::User,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // First promote user3 to admin
        assert!(change_user_role(&conn, &admin2_auth, &user3.id, UserRole::Admin).is_ok());
        
        // Then demote admin2 to user
        assert!(change_user_role(&conn, &user3_auth, &regular_user.id, UserRole::User).is_ok());
        
        // Now user3 is the last admin, trying to demote themselves should fail
        assert!(change_user_role(&conn, &user3_auth, &user3.id, UserRole::User).is_err());
    }
    
    #[test]
    fn test_is_last_admin() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create two admin users
        let admin1 = create_test_user(&conn, UserRole::Admin);
        let admin2 = create_test_user(&conn, UserRole::Admin);
        
        // Neither should be the last admin
        assert!(!is_last_admin(&conn, &admin1.id).unwrap());
        assert!(!is_last_admin(&conn, &admin2.id).unwrap());
        
        // Create auth result for admin1
        let admin1_auth = AuthResult {
            user_id: admin1.id.clone(),
            username: admin1.username.clone(),
            role: UserRole::Admin,
            tfa_verified: true,
            token_id: "token_id".to_string(),
            last_activity: Utc::now(),
        };
        
        // Demote admin2 to user
        assert!(change_user_role(&conn, &admin1_auth, &admin2.id, UserRole::User).is_ok());
        
        // Now admin1 should be the last admin
        assert!(is_last_admin(&conn, &admin1.id).unwrap());
        
        // And admin2 shouldn't be an admin anymore
        assert!(!is_last_admin(&conn, &admin2.id).unwrap());
    }
} 