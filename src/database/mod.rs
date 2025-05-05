use anyhow::{Result, Context};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, Savepoint, Transaction};
use std::path::Path;
use std::sync::Arc;
use lazy_static::lazy_static;
use log::{info, error, debug};

use crate::config;
use crate::security;

mod schema;
pub mod models;

// Database connection pool - lazy initialized
lazy_static! {
    static ref DB_POOL: Arc<Option<Pool<SqliteConnectionManager>>> = Arc::new(None);
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
    
    // Create connection manager
    let manager = SqliteConnectionManager::file(db_path);
    
    // Create connection pool
    let pool = Pool::builder()
        .max_size(config.database.max_connections)
        .build(manager)
        .context("Failed to create database connection pool")?;
    
    // Get a connection to test and initialize the database
    let conn = pool.get().context("Failed to get a database connection")?;
    
    // Create schema if database doesn't exist
    if !db_exists {
        debug!("Creating new database at {}", db_path);
        schema::create_schema(&conn).context("Failed to create database schema")?;
        info!("Database schema created successfully");
    } else {
        debug!("Using existing database at {}", db_path);
        // TODO: Implement database migration if needed
    }
    
    // TODO: Initialize database encryption if enabled
    if config.database.encrypt {
        debug!("Database encryption is enabled, but not yet implemented");
        // In a real implementation, we would use SQLCipher or similar
        // security::initialize_database_encryption(&conn)?;
    }
    
    // Store the pool in the global variable (for a real application, use proper DI pattern)
    // For now, we'll just use the pool directly
    
    info!("Database initialized successfully");
    Ok(())
}

/// Get a connection from the pool
pub fn get_connection() -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let config = config::get_config();
    let db_path = &config.database.path;
    
    // Create manager and pool if they don't exist
    let manager = SqliteConnectionManager::file(db_path);
    let pool = Pool::builder()
        .max_size(config.database.max_connections)
        .build(manager)
        .context("Failed to create database connection pool")?;
    
    // Get connection from pool
    let conn = pool.get().context("Failed to get a database connection")?;
    
    Ok(conn)
}

/// Get a transaction from a connection
pub fn get_transaction(conn: &Connection) -> Result<Transaction> {
    let tx = conn.transaction().context("Failed to start a transaction")?;
    Ok(tx)
}

/// Get a savepoint from a connection
pub fn get_savepoint(conn: &Connection, name: &str) -> Result<Savepoint> {
    let sp = conn.savepoint_with_name(name).context("Failed to create a savepoint")?;
    Ok(sp)
} 