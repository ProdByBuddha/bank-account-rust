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

// For future migrations, add functions like:
// fn migrate_v1_to_v2(conn: &Connection) -> Result<()> { ... }

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
        let conn = Connection::open(&db_path).unwrap();
        
        // Run migrations
        run_migrations(&conn).unwrap();
        
        // Check final version
        let version = get_database_version(&conn).unwrap();
        assert_eq!(version, CURRENT_VERSION, "Version should be updated to current");
    }
} 