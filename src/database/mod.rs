use anyhow::{Result, Context};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, Savepoint, Transaction};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use lazy_static::lazy_static;
use log::{info, error, debug, warn};

use crate::config;
use crate::security;

mod schema;
pub mod models;
mod migrations;
#[cfg(test)]
mod tests;

// Database encryption key
lazy_static! {
    static ref DB_ENCRYPTION_KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);
    static ref DB_POOL: RwLock<Option<Pool<SqliteConnectionManager>>> = RwLock::new(None);
}

/// Initialize the database encryption key
fn initialize_encryption_key() -> Result<()> {
    let config = config::get_config();
    
    if !config.database.encrypt {
        debug!("Database encryption is disabled");
        return Ok(());
    }
    
    debug!("Initializing database encryption key");
    
    let key = security::generate_encryption_key();
    
    // In a real production system, this key would be stored securely
    // and potentially encrypted with a master key derived from a password
    // or stored in a hardware security module.
    // 
    // For this implementation, we'll store it in memory only
    
    // Store the key in the global variable
    *DB_ENCRYPTION_KEY.write().unwrap() = Some(key);
    
    debug!("Database encryption key initialized");
    Ok(())
}

/// Get the database encryption key
fn get_encryption_key() -> Result<[u8; 32]> {
    match *DB_ENCRYPTION_KEY.read().unwrap() {
        Some(key) => Ok(key),
        None => {
            warn!("Database encryption key not initialized");
            Err(anyhow::anyhow!("Database encryption key not initialized"))
        }
    }
}

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
    
    // Initialize encryption if enabled
    if config.database.encrypt {
        initialize_encryption_key().context("Failed to initialize database encryption")?;
    }
    
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
                let mut conn_mut = conn.clone();
                configure_connection(&mut conn_mut)?;
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
    
    let key = get_encryption_key()?;
    security::encrypt_string(data, &key)
}

/// Decrypt data retrieved from the database
pub fn decrypt_data(data: &str) -> Result<String> {
    let config = config::get_config();
    if !config.database.encrypt {
        return Ok(data.to_string());
    }
    
    let key = get_encryption_key()?;
    security::decrypt_string(data, &key)
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