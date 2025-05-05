use anyhow::{Result, Context, anyhow};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, Savepoint, Transaction};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use lazy_static::lazy_static;
use log::{info, error, debug, warn};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid;

use crate::config;
use crate::security;

mod schema;
pub mod models;
mod migrations;
pub mod backup;
#[cfg(test)]
mod tests;

use self::models::{User, UserRole, Account, AccountType, AccountStatus, Transaction, 
    TransactionType, TransactionStatus, AuditLog, AuditEventType, Token};

// Database connection pool
lazy_static! {
    static ref DB_POOL: RwLock<Option<Pool<SqliteConnectionManager>>> = RwLock::new(None);
}

// Constants for user authentication
pub const MAX_FAILED_LOGIN_ATTEMPTS: u32 = 5;

/// Initialize the database
pub fn initialize() -> Result<()> {
    let config = config::get_config();
    let db_path = &config.database.path;
    
    // Create directory if it doesn't exist
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }
    }
    
    // Check if database exists
    let db_exists = Path::new(db_path).exists();
    
    // Create connection manager
    let manager = SqliteConnectionManager::file(db_path);
    
    // Create connection pool
    let pool = Pool::builder()
        .max_size(config.database.max_connections)
        .build(manager)
        .context("Failed to create database connection pool")?;
    
    // Get a connection to test and initialize the database
    let mut conn = pool.get().context("Failed to get a database connection")?;
    
    // Configure database connection
    configure_connection(&mut conn)?;
    
    // Create schema if database doesn't exist
    if !db_exists {
        debug!("Creating new database at {}", db_path);
        schema::create_schema(&mut conn).context("Failed to create database schema")?;
        schema::create_audit_triggers(&mut conn).context("Failed to create audit triggers")?;
        info!("Database schema created successfully");
    } else {
        debug!("Using existing database at {}", db_path);
        // Run migrations if needed
        migrations::run_migrations(&mut conn)?;
    }
    
    // Store the pool in the global variable
    *DB_POOL.write().unwrap() = Some(pool);
    
    info!("Database initialized successfully");
    Ok(())
}

/// Configure database connection with appropriate settings
fn configure_connection(conn: &mut Connection) -> Result<()> {
    // Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", [])
        .context("Failed to enable foreign keys")?;
    
    // Set journal mode to WAL for better concurrent access
    conn.execute("PRAGMA journal_mode = WAL", [])
        .context("Failed to set journal mode to WAL")?;
    
    // Set synchronous mode to NORMAL for better performance while maintaining safety
    conn.execute("PRAGMA synchronous = NORMAL", [])
        .context("Failed to set synchronous mode")?;
    
    // Set temp store to memory for better performance
    conn.execute("PRAGMA temp_store = MEMORY", [])
        .context("Failed to set temp store to memory")?;
    
    // Set busy timeout to avoid immediate failure on concurrent access
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .context("Failed to set busy timeout")?;
    
    // Apply encryption if enabled
    let config = config::get_config();
    if config.database.encrypt {
        // In a real implementation with SQLCipher, this would use the KEY pragma
        // conn.execute("PRAGMA key = ?", params![key_as_hex_string])?;
        
        // For this implementation, we'll simulate encryption by using our
        // encryption functions on data before storing it
        debug!("Database encryption is enabled");
    }
    
    Ok(())
}

/// Get a connection from the pool
pub fn get_connection() -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    match DB_POOL.read().unwrap().as_ref() {
        Some(pool) => {
            let conn = pool.get().context("Failed to get a database connection from the pool")?;
            Ok(conn)
        }
        None => {
            // Fallback if pool is not initialized
            let config = config::get_config();
            let db_path = &config.database.path;
            
            debug!("Database pool not initialized, creating a new connection to {}", db_path);
            
            // Create manager and pool
            let manager = SqliteConnectionManager::file(db_path);
            let pool = Pool::builder()
                .max_size(config.database.max_connections)
                .build(manager)
                .context("Failed to create database connection pool")?;
            
            // Get connection from pool
            let conn = pool.get().context("Failed to get a database connection")?;
            
            // Configure connection
            {
                // Get a new connection with the same config to configure
                let mut new_conn = Connection::open(db_path)?;
                configure_connection(&mut new_conn)?;
            }
            
            Ok(conn)
        }
    }
}

/// Get a transaction from a connection
pub fn get_transaction(conn: &mut Connection) -> Result<Transaction> {
    let tx = conn.transaction().context("Failed to start a transaction")?;
    Ok(tx)
}

/// Get a savepoint from a connection
pub fn get_savepoint<'a>(conn: &'a mut Connection, name: &str) -> Result<Savepoint<'a>> {
    let sp = conn.savepoint_with_name(name).context("Failed to create a savepoint")?;
    Ok(sp)
}

/// Encrypt data before storing in the database
pub fn encrypt_data(data: &str) -> Result<String> {
    let config = config::get_config();
    if !config.database.encrypt {
        return Ok(data.to_string());
    }
    
    // Use the enhanced encryption module
    security::encrypt_with_current_key(data)
}

/// Decrypt data retrieved from the database
pub fn decrypt_data(data: &str) -> Result<String> {
    let config = config::get_config();
    if !config.database.encrypt {
        return Ok(data.to_string());
    }
    
    // Use the enhanced encryption module
    security::decrypt_with_current_key(data)
}

/// Create a backup of the database
pub fn create_backup(backup_path: &str) -> Result<()> {
    let conn = get_connection()?;
    let mut backup_dest = Connection::open(backup_path)
        .context(format!("Failed to open backup destination: {}", backup_path))?;
    
    // Use the SQLite backup API
    let backup = rusqlite::backup::Backup::new(&conn, &mut backup_dest)
        .context("Failed to initialize backup")?;
    
    // Perform the backup
    backup.run_to_completion(100, std::time::Duration::from_millis(250), None)
        .context("Failed to complete backup")?;
    
    info!("Database backup created successfully at {}", backup_path);
    Ok(())
}

/// Restore a backup of the database
pub fn restore_backup(backup_path: &str) -> Result<()> {
    let config = config::get_config();
    let db_path = &config.database.path;
    
    // Close all connections
    *DB_POOL.write().unwrap() = None;
    
    // Open the backup file
    let backup_conn = Connection::open(backup_path)
        .context(format!("Failed to open backup file: {}", backup_path))?;
    
    // Open the main database
    let mut main_conn = Connection::open(db_path)
        .context(format!("Failed to open database: {}", db_path))?;
    
    // Use the SQLite backup API
    let backup = rusqlite::backup::Backup::new(&backup_conn, &mut main_conn)
        .context("Failed to initialize backup restoration")?;
    
    // Perform the restoration
    backup.run_to_completion(100, std::time::Duration::from_millis(250), None)
        .context("Failed to complete backup restoration")?;
    
    // Reinitialize database
    initialize()?;
    
    info!("Database backup restored successfully from {}", backup_path);
    Ok(())
}

/// Create a new token in the database
pub fn store_token(
    conn: &Connection,
    token: &Token,
) -> Result<()> {
    conn.execute(
        "INSERT INTO tokens (
            id, user_id, token_hash, expires_at, revoked, 
            device_info, ip_address, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            token.id,
            token.user_id,
            token.token_hash,
            token.expires_at,
            token.revoked as i32,
            token.device_info,
            token.ip_address,
            token.created_at,
            token.revoked_at,
        ],
    )
    .context("Failed to store token in database")?;

    debug!("Stored token {} for user {}", token.id, token.user_id);
    Ok(())
}

/// Find a token by its token ID (jti claim)
pub fn find_token_by_id(conn: &Connection, token_id: &str) -> Result<Option<Token>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, token_hash, expires_at, revoked, 
                device_info, ip_address, created_at, revoked_at
         FROM tokens 
         WHERE id = ?",
    )
    .context("Failed to prepare statement to find token")?;

    let token = stmt
        .query_row(params![token_id], |row| {
            Ok(Token {
                id: row.get(0)?,
                user_id: row.get(1)?,
                token_hash: row.get(2)?,
                expires_at: row.get(3)?,
                revoked: row.get::<_, i32>(4)? != 0,
                device_info: row.get(5)?,
                ip_address: row.get(6)?,
                created_at: row.get(7)?,
                revoked_at: row.get(8)?,
            })
        })
        .optional()
        .context("Failed to query token")?;

    Ok(token)
}

/// Find token by its hash
pub fn find_token_by_hash(conn: &Connection, token_hash: &str) -> Result<Option<Token>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, token_hash, expires_at, revoked, 
                device_info, ip_address, created_at, revoked_at
         FROM tokens 
         WHERE token_hash = ?",
    )
    .context("Failed to prepare statement to find token by hash")?;

    let token = stmt
        .query_row(params![token_hash], |row| {
            Ok(Token {
                id: row.get(0)?,
                user_id: row.get(1)?,
                token_hash: row.get(2)?,
                expires_at: row.get(3)?,
                revoked: row.get::<_, i32>(4)? != 0,
                device_info: row.get(5)?,
                ip_address: row.get(6)?,
                created_at: row.get(7)?,
                revoked_at: row.get(8)?,
            })
        })
        .optional()
        .context("Failed to query token by hash")?;

    Ok(token)
}

/// Revoke a token
pub fn revoke_token(conn: &Connection, token_id: &str) -> Result<bool> {
    let now = Utc::now();
    let result = conn.execute(
        "UPDATE tokens 
         SET revoked = 1, revoked_at = ? 
         WHERE id = ? AND revoked = 0",
        params![now, token_id],
    )
    .context("Failed to revoke token")?;

    Ok(result > 0)
}

/// Revoke all tokens for a user
pub fn revoke_all_user_tokens(conn: &Connection, user_id: &str) -> Result<usize> {
    let now = Utc::now();
    let result = conn.execute(
        "UPDATE tokens 
         SET revoked = 1, revoked_at = ? 
         WHERE user_id = ? AND revoked = 0",
        params![now, user_id],
    )
    .context("Failed to revoke all user tokens")?;

    Ok(result as usize)
}

/// Check if a token is valid (exists, not expired, not revoked)
pub fn is_token_valid(conn: &Connection, token_id: &str) -> Result<bool> {
    let now = Utc::now();
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM tokens 
         WHERE id = ? AND revoked = 0 AND expires_at > ?",
    )
    .context("Failed to prepare statement to check token validity")?;

    let count: i64 = stmt
        .query_row(params![token_id, now], |row| row.get(0))
        .context("Failed to check token validity")?;

    Ok(count > 0)
}

/// Clean up expired tokens
pub fn clean_expired_tokens(conn: &Connection) -> Result<usize> {
    let now = Utc::now();
    let result = conn.execute(
        "DELETE FROM tokens WHERE expires_at < ?",
        params![now],
    )
    .context("Failed to clean up expired tokens")?;

    debug!("Cleaned up {} expired tokens", result);
    Ok(result as usize)
}

/// Get user by username
pub fn get_user_by_username(conn: &Connection, username: &str) -> Result<Option<User>> {
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
            let role = crate::database::models::UserRole::from_str(&role_str)
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
        Err(e) => Err(anyhow!("Failed to get user by username: {}", e)),
    }
}

/// Update failed login attempts for a user
pub fn update_failed_login_attempts(conn: &Connection, user_id: &str, attempts: u32) -> Result<()> {
    conn.execute(
        "UPDATE users SET 
            failed_login_attempts = ?1,
            updated_at = ?2
         WHERE id = ?3",
        params![
            attempts,
            Utc::now().to_rfc3339(),
            user_id
        ]
    ).context("Failed to update failed login attempts")?;
    
    Ok(())
}

/// Lock a user account
pub fn lock_user_account(conn: &Connection, user_id: &str) -> Result<()> {
    let now = Utc::now();
    conn.execute(
        "UPDATE users SET 
            account_locked = 1,
            lockout_time = ?1,
            updated_at = ?2
         WHERE id = ?3",
        params![
            now.to_rfc3339(),
            now.to_rfc3339(),
            user_id
        ]
    ).context("Failed to lock user account")?;
    
    // Create audit log for account lockout
    // In a real app, add more detailed info about the lockout
    add_audit_log(
        conn,
        "account_locked",
        Some(user_id),
        Some("Account locked due to too many failed login attempts"),
    )?;
    
    Ok(())
}

/// Reset failed login attempts for a user
pub fn reset_failed_login_attempts(conn: &Connection, user_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET 
            failed_login_attempts = 0,
            account_locked = 0,
            lockout_time = NULL,
            updated_at = ?1
         WHERE id = ?2",
        params![
            Utc::now().to_rfc3339(),
            user_id
        ]
    ).context("Failed to reset failed login attempts")?;
    
    Ok(())
}

/// Update last login time for a user
pub fn update_last_login(conn: &Connection, user_id: &str) -> Result<()> {
    let now = Utc::now();
    conn.execute(
        "UPDATE users SET 
            last_login = ?1,
            updated_at = ?2
         WHERE id = ?3",
        params![
            now.to_rfc3339(),
            now.to_rfc3339(),
            user_id
        ]
    ).context("Failed to update last login time")?;
    
    // Create audit log for login
    add_audit_log(
        conn,
        "user_login",
        Some(user_id),
        Some("User logged in successfully"),
    )?;
    
    Ok(())
}

/// Add an audit log entry
pub fn add_audit_log(
    conn: &Connection,
    event_type: &str,
    user_id: Option<&str>,
    details: Option<&str>
) -> Result<()> {
    let audit_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    
    conn.execute(
        "INSERT INTO audit_logs (id, event_type, user_id, details, timestamp)
        VALUES (?1, ?2, ?3, ?4, ?5)",
        params![audit_id, event_type, user_id, details, now]
    ).context("Failed to insert audit log")?;
    
    Ok(())
}

/// Alias for get_connection for better code readability
pub fn connect() -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    get_connection()
}

/// Close all database connections
pub fn close_all_connections() -> Result<()> {
    // Acquire write lock to replace the pool
    let mut pool_guard = DB_POOL.write().unwrap();
    
    // Drop the existing pool if it exists
    *pool_guard = None;
    
    debug!("All database connections closed");
    Ok(())
} 