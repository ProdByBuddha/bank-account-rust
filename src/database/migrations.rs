use anyhow::{Result, Context};
use log::{debug, info, warn};
use rusqlite::Connection;
use std::collections::HashMap;

// Database schema version
const CURRENT_VERSION: u32 = 1;

/// Run any necessary database migrations
pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    debug!("Checking database version");
    
    // Get current database version
    let version = get_database_version(conn)?;
    
    if version == CURRENT_VERSION {
        debug!("Database schema is up to date (version {})", version);
        return Ok(());
    }
    
    info!("Migrating database from version {} to {}", version, CURRENT_VERSION);
    
    // Use a transaction for the migrations to ensure atomicity
    let tx = conn.transaction().context("Failed to start transaction for migrations")?;
    
    // Apply each migration in sequence
    for v in version..CURRENT_VERSION {
        let migration_fn = match v {
            0 => migrate_v0_to_v1,
            // Add more migrations here as needed
            _ => {
                warn!("No migration function found for version {}", v);
                continue;
            }
        };
        
        debug!("Running migration from version {} to {}", v, v + 1);
        migration_fn(&tx).context(format!("Failed to migrate from version {} to {}", v, v + 1))?;
    }
    
    // Update the database version
    set_database_version(&tx, CURRENT_VERSION)?;
    
    // Commit the transaction
    tx.commit().context("Failed to commit migration transaction")?;
    
    info!("Database migration completed successfully to version {}", CURRENT_VERSION);
    Ok(())
}

/// Get the current database version
fn get_database_version(conn: &Connection) -> Result<u32> {
    // Check if the version table exists
    let version_table_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='database_version')",
        [],
        |row| row.get(0),
    ).unwrap_or(false);
    
    // If the table doesn't exist, create it and set version to 0
    if !version_table_exists {
        conn.execute(
            "CREATE TABLE database_version (version INTEGER NOT NULL)",
            [],
        ).context("Failed to create database_version table")?;
        
        conn.execute(
            "INSERT INTO database_version (version) VALUES (0)",
            [],
        ).context("Failed to initialize database version")?;
        
        return Ok(0);
    }
    
    // Get the current version
    let version: u32 = conn.query_row(
        "SELECT version FROM database_version",
        [],
        |row| row.get(0),
    ).context("Failed to get database version")?;
    
    Ok(version)
}

/// Set the database version
fn set_database_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "UPDATE database_version SET version = ?",
        [version],
    ).context("Failed to update database version")?;
    
    Ok(())
}

/// Migration from version 0 to version 1
fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
    // In the initial implementation, version 0 to 1 just sets up the base schema
    // which is already created in schema.rs. This is just a placeholder for
    // future migrations.
    
    debug!("Migration from version 0 to 1 completed");
    Ok(())
}

/// Apply all migrations in order
pub fn apply_migrations(conn: &Connection) -> Result<()> {
    info!("Applying database migrations...");
    
    // Keep track of applied migrations
    create_migrations_table(conn)?;
    
    // Apply migrations in order
    apply_migration_if_needed(conn, "001_initial_schema", migration_001_initial_schema)?;
    apply_migration_if_needed(conn, "002_add_totp_tables", migration_002_add_totp_tables)?;
    apply_migration_if_needed(conn, "003_add_transaction_tables", migration_003_add_transaction_tables)?;
    
    info!("Database migrations completed successfully");
    Ok(())
}

/// Migration 003: Add scheduled and recurring transaction tables
fn migration_003_add_transaction_tables(conn: &Connection) -> Result<()> {
    info!("Applying migration: Add transaction tables");
    
    // Add transaction reference_id column if it doesn't exist
    let columns = conn.prepare("PRAGMA table_info(transactions)")?
        .query_map([], |row| Ok(row.get::<_, String>(1)?))?
        .collect::<Result<Vec<String>, _>>()?;
    
    if !columns.contains(&"reference_id".to_string()) {
        conn.execute(
            "ALTER TABLE transactions ADD COLUMN reference_id TEXT",
            [],
        )?;
    }
    
    if !columns.contains(&"to_account_id".to_string()) {
        conn.execute(
            "ALTER TABLE transactions ADD COLUMN to_account_id TEXT REFERENCES accounts(id)",
            [],
        )?;
    }
    
    // Create scheduled transactions table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scheduled_transactions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            to_account_id TEXT,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            scheduled_date TEXT NOT NULL,
            reference_id TEXT NOT NULL,
            encrypted_details TEXT,
            processed INTEGER NOT NULL DEFAULT 0,
            processed_at TEXT,
            transaction_id TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            last_failure TEXT,
            last_error TEXT,
            cancelled INTEGER NOT NULL DEFAULT 0,
            cancelled_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (to_account_id) REFERENCES accounts(id),
            FOREIGN KEY (transaction_id) REFERENCES transactions(id)
        )",
        [],
    )?;
    
    // Create recurring transactions table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS recurring_transactions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            to_account_id TEXT,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            frequency TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT,
            next_date TEXT NOT NULL,
            reference_base TEXT NOT NULL,
            encrypted_details TEXT,
            failure_count INTEGER NOT NULL DEFAULT 0,
            last_failure TEXT,
            last_error TEXT,
            last_processed_at TEXT,
            last_transaction_id TEXT,
            completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT,
            cancelled INTEGER NOT NULL DEFAULT 0,
            cancelled_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (to_account_id) REFERENCES accounts(id),
            FOREIGN KEY (last_transaction_id) REFERENCES transactions(id)
        )",
        [],
    )?;
    
    // Create indexes
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_transactions_user_id 
         ON scheduled_transactions(user_id)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_transactions_scheduled_date 
         ON scheduled_transactions(scheduled_date)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scheduled_transactions_processed 
         ON scheduled_transactions(processed)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recurring_transactions_user_id 
         ON recurring_transactions(user_id)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recurring_transactions_next_date 
         ON recurring_transactions(next_date)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recurring_transactions_completed 
         ON recurring_transactions(completed)",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_transactions_reference_id 
         ON transactions(reference_id)",
        [],
    )?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::path::Path;
    
    #[test]
    fn test_version_management() {
        // Create a temporary database
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_migration.db");
        let conn = Connection::open(&db_path).unwrap();
        
        // Check initial version
        let initial_version = get_database_version(&conn).unwrap();
        assert_eq!(initial_version, 0, "Initial version should be 0");
        
        // Set version to 1
        set_database_version(&conn, 1).unwrap();
        
        // Check version again
        let new_version = get_database_version(&conn).unwrap();
        assert_eq!(new_version, 1, "Version should be updated to 1");
    }
    
    #[test]
    fn test_run_migrations() {
        // Create a temporary database
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_migration.db");
        let mut conn = Connection::open(&db_path).unwrap();
        
        // Run migrations
        run_migrations(&mut conn).unwrap();
        
        // Check final version
        let version = get_database_version(&conn).unwrap();
        assert_eq!(version, CURRENT_VERSION, "Version should be updated to current");
    }
} 