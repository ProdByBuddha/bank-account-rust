use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local, Utc};
use log::{debug, error, info, warn};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::audit;
use crate::config;
use crate::security;

/// Metadata for a database backup
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub id: String,
    pub filename: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub encrypted: bool,
    pub description: Option<String>,
    pub checksum: String,
    pub version: String,
    pub retention_policy: Option<String>,
    pub user_id: Option<String>,
    pub verified: bool,
}

/// Database backup manager
pub struct BackupManager {
    backup_dir: PathBuf,
    metadata_file: PathBuf,
    db_path: String,
    metadata: HashMap<String, BackupMetadata>,
    max_backups: usize,
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new() -> Result<Self> {
        let config = config::get_config();
        let backup_dir = PathBuf::from(&config.database.backup_dir);
        
        // Create backup directory if it doesn't exist
        if !backup_dir.exists() {
            fs::create_dir_all(&backup_dir)
                .context(format!("Failed to create backup directory: {:?}", backup_dir))?;
            info!("Created backup directory: {:?}", backup_dir);
        }
        
        let metadata_file = backup_dir.join("backup_metadata.json");
        let mut metadata = HashMap::new();
        
        // Load existing metadata if it exists
        if metadata_file.exists() {
            let mut file = File::open(&metadata_file)
                .context(format!("Failed to open backup metadata file: {:?}", metadata_file))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .context("Failed to read backup metadata file")?;
            
            // If the file exists but is empty or invalid JSON, just start with an empty metadata map
            if !contents.is_empty() {
                match serde_json::from_str::<HashMap<String, BackupMetadata>>(&contents) {
                    Ok(loaded_metadata) => {
                        metadata = loaded_metadata;
                        debug!("Loaded {} backup metadata entries", metadata.len());
                    },
                    Err(e) => {
                        warn!("Failed to parse backup metadata file, starting with empty metadata: {}", e);
                    }
                }
            }
        }
        
        Ok(Self {
            backup_dir,
            metadata_file,
            db_path: config.database.path.clone(),
            metadata,
            max_backups: config.database.max_backups.unwrap_or(10),
        })
    }
    
    /// Save the current metadata to disk
    fn save_metadata(&self) -> Result<()> {
        let contents = serde_json::to_string_pretty(&self.metadata)
            .context("Failed to serialize backup metadata")?;
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.metadata_file)
            .context(format!("Failed to open metadata file for writing: {:?}", self.metadata_file))?;
            
        file.write_all(contents.as_bytes())
            .context("Failed to write backup metadata")?;
            
        debug!("Saved backup metadata to {:?}", self.metadata_file);
        Ok(())
    }
    
    /// Create a new backup with optional description
    pub fn create_backup(&mut self, description: Option<String>, user_id: Option<&str>) -> Result<String> {
        let backup_id = Uuid::new_v4().to_string();
        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("backup_{}_{}.db", timestamp, &backup_id[..8]);
        let backup_path = self.backup_dir.join(&filename);
        
        info!("Creating database backup to: {:?}", backup_path);
        
        // Perform the backup
        self.perform_backup(&backup_path)?;
        
        // Calculate checksum of the backup file
        let checksum = self.calculate_file_checksum(&backup_path)?;
        
        // Encrypt the backup if configured
        let config = config::get_config();
        let encrypted = config.database.encrypt_backups;
        
        if encrypted {
            debug!("Encrypting backup file");
            let encrypted_path = backup_path.with_extension("db.enc");
            self.encrypt_backup(&backup_path, &encrypted_path)?;
            
            // Remove the unencrypted backup
            fs::remove_file(&backup_path)
                .context(format!("Failed to remove unencrypted backup file: {:?}", backup_path))?;
            
            // Update the filename to the encrypted version
            let enc_filename = format!("{}.enc", filename);
            
            // Create metadata for the encrypted backup
            let metadata = BackupMetadata {
                id: backup_id.clone(),
                filename: enc_filename,
                created_at: Utc::now(),
                size_bytes: fs::metadata(&encrypted_path)?.len(),
                encrypted,
                description,
                checksum,
                version: env!("CARGO_PKG_VERSION").to_string(),
                retention_policy: None,
                user_id: user_id.map(|id| id.to_string()),
                verified: false,
            };
            
            self.metadata.insert(backup_id.clone(), metadata);
        } else {
            // Create metadata for the unencrypted backup
            let metadata = BackupMetadata {
                id: backup_id.clone(),
                filename,
                created_at: Utc::now(),
                size_bytes: fs::metadata(&backup_path)?.len(),
                encrypted,
                description,
                checksum,
                version: env!("CARGO_PKG_VERSION").to_string(),
                retention_policy: None,
                user_id: user_id.map(|id| id.to_string()),
                verified: false,
            };
            
            self.metadata.insert(backup_id.clone(), metadata);
        }
        
        // Save updated metadata
        self.save_metadata()?;
        
        // Apply retention policy
        self.apply_retention_policy()?;
        
        // Add audit log
        if let Some(user_id) = user_id {
            audit::log_event(
                "BACKUP_CREATED",
                Some(user_id),
                Some(&format!("Created backup with ID: {}", backup_id)),
            )?;
        }
        
        info!("Database backup completed with ID: {}", backup_id);
        Ok(backup_id)
    }
    
    /// Perform the actual backup using SQLite backup API
    fn perform_backup(&self, backup_path: &Path) -> Result<()> {
        let conn = super::get_connection()?;
        let mut backup_conn = Connection::open(backup_path)
            .context(format!("Failed to open backup destination: {:?}", backup_path))?;
        
        // Use the SQLite backup API
        let backup = rusqlite::backup::Backup::new(&conn, &mut backup_conn)
            .context("Failed to initialize backup")?;
        
        // Perform the backup in steps for progress reporting
        let mut remaining = backup.step(-1)
            .context("Failed to perform backup step")?;
            
        while remaining > 0 {
            remaining = backup.step(100)
                .context("Failed to perform backup step")?;
            debug!("Backup progress: {} pages remaining", remaining);
        }
        
        debug!("Raw database backup completed to {:?}", backup_path);
        Ok(())
    }
    
    /// Calculate SHA-256 checksum of a file
    fn calculate_file_checksum(&self, file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path)
            .context(format!("Failed to open file for checksum calculation: {:?}", file_path))?;
        
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .context("Failed to read file for checksum calculation")?;
                
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        let hash = hasher.finalize();
        Ok(format!("{:x}", hash))
    }
    
    /// Encrypt a backup file
    fn encrypt_backup(&self, source_path: &Path, dest_path: &Path) -> Result<()> {
        let mut source_file = File::open(source_path)
            .context(format!("Failed to open backup file for encryption: {:?}", source_path))?;
            
        let mut plaintext = Vec::new();
        source_file.read_to_end(&mut plaintext)
            .context("Failed to read backup file for encryption")?;
            
        // Encrypt the data
        let ciphertext = security::encrypt_data(&plaintext)
            .context("Failed to encrypt backup data")?;
            
        // Write the encrypted data to the destination file
        let mut dest_file = File::create(dest_path)
            .context(format!("Failed to create encrypted backup file: {:?}", dest_path))?;
            
        dest_file.write_all(&ciphertext)
            .context("Failed to write encrypted backup data")?;
            
        debug!("Backup encrypted successfully");
        Ok(())
    }
    
    /// Decrypt a backup file
    fn decrypt_backup(&self, source_path: &Path, dest_path: &Path) -> Result<()> {
        let mut source_file = File::open(source_path)
            .context(format!("Failed to open encrypted backup file: {:?}", source_path))?;
            
        let mut ciphertext = Vec::new();
        source_file.read_to_end(&mut ciphertext)
            .context("Failed to read encrypted backup file")?;
            
        // Decrypt the data
        let plaintext = security::decrypt_data(&ciphertext)
            .context("Failed to decrypt backup data")?;
            
        // Write the decrypted data to the destination file
        let mut dest_file = File::create(dest_path)
            .context(format!("Failed to create decrypted backup file: {:?}", dest_path))?;
            
        dest_file.write_all(&plaintext)
            .context("Failed to write decrypted backup data")?;
            
        debug!("Backup decrypted successfully");
        Ok(())
    }
    
    /// Restore a database from a backup by ID
    pub fn restore_backup(&self, backup_id: &str, user_id: Option<&str>) -> Result<()> {
        let metadata = self.metadata.get(backup_id)
            .ok_or_else(|| anyhow!("Backup with ID {} not found", backup_id))?;
            
        let backup_path = self.backup_dir.join(&metadata.filename);
        
        if !backup_path.exists() {
            return Err(anyhow!("Backup file not found: {:?}", backup_path));
        }
        
        // Close all existing database connections
        debug!("Closing all database connections");
        super::close_all_connections();
        
        let temp_path = self.backup_dir.join("temp_restore.db");
        
        // If the backup is encrypted, decrypt it first
        if metadata.encrypted {
            debug!("Decrypting backup file");
            self.decrypt_backup(&backup_path, &temp_path)?;
        } else {
            fs::copy(&backup_path, &temp_path)
                .context(format!("Failed to copy backup file to temp location: {:?}", backup_path))?;
        }
        
        // Verify the backup integrity by calculating its checksum
        let calculated_checksum = self.calculate_file_checksum(&temp_path)?;
        if calculated_checksum != metadata.checksum {
            fs::remove_file(&temp_path).ok(); // Clean up temp file
            return Err(anyhow!("Backup integrity check failed: checksum mismatch"));
        }
        
        debug!("Backup integrity verified successfully");
        
        // Perform the restoration
        info!("Restoring database from backup {}", backup_id);
        
        let db_path = PathBuf::from(&self.db_path);
        
        // Create a backup of the current database before restoration
        let current_backup_path = db_path.with_extension("db.pre_restore");
        fs::copy(&db_path, &current_backup_path)
            .context(format!("Failed to create safety backup of current database: {:?}", current_backup_path))?;
            
        debug!("Created safety backup of current database at {:?}", current_backup_path);
        
        // Copy the decrypted backup to the database location
        fs::copy(&temp_path, &db_path)
            .context(format!("Failed to restore database from backup: {:?}", temp_path))?;
            
        // Clean up temp file
        fs::remove_file(&temp_path).ok();
        
        // Re-initialize the database connection
        debug!("Re-initializing database connection");
        super::initialize()?;
        
        // Add audit log
        if let Some(user_id) = user_id {
            audit::log_event(
                "BACKUP_RESTORED",
                Some(user_id),
                Some(&format!("Restored database from backup with ID: {}", backup_id)),
            )?;
        }
        
        info!("Database restored successfully from backup {}", backup_id);
        Ok(())
    }
    
    /// Verify a backup's integrity
    pub fn verify_backup(&mut self, backup_id: &str) -> Result<bool> {
        let metadata = match self.metadata.get(backup_id) {
            Some(md) => md.clone(),
            None => return Err(anyhow!("Backup with ID {} not found", backup_id)),
        };
        
        let backup_path = self.backup_dir.join(&metadata.filename);
        
        if !backup_path.exists() {
            return Err(anyhow!("Backup file not found: {:?}", backup_path));
        }
        
        let temp_path = self.backup_dir.join("temp_verify.db");
        
        // If the backup is encrypted, decrypt it first
        if metadata.encrypted {
            debug!("Decrypting backup for verification");
            self.decrypt_backup(&backup_path, &temp_path)?;
        } else {
            fs::copy(&backup_path, &temp_path)
                .context(format!("Failed to copy backup file for verification: {:?}", backup_path))?;
        }
        
        // Calculate the checksum
        let calculated_checksum = self.calculate_file_checksum(&temp_path)?;
        
        // Clean up temp file
        fs::remove_file(&temp_path).ok();
        
        // Check if checksums match
        let verified = calculated_checksum == metadata.checksum;
        
        // Update metadata to reflect verification
        if let Some(md) = self.metadata.get_mut(backup_id) {
            md.verified = verified;
            self.save_metadata()?;
        }
        
        if verified {
            info!("Backup {} verified successfully", backup_id);
        } else {
            warn!("Backup {} verification failed: checksum mismatch", backup_id);
        }
        
        Ok(verified)
    }
    
    /// List all backups
    pub fn list_backups(&self) -> Vec<&BackupMetadata> {
        // Sort by creation date, newest first
        let mut backups: Vec<&BackupMetadata> = self.metadata.values().collect();
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        backups
    }
    
    /// Get backup by ID
    pub fn get_backup(&self, backup_id: &str) -> Option<&BackupMetadata> {
        self.metadata.get(backup_id)
    }
    
    /// Delete a backup by ID
    pub fn delete_backup(&mut self, backup_id: &str, user_id: Option<&str>) -> Result<bool> {
        let metadata = match self.metadata.get(backup_id) {
            Some(md) => md.clone(),
            None => return Err(anyhow!("Backup with ID {} not found", backup_id)),
        };
        
        let backup_path = self.backup_dir.join(&metadata.filename);
        
        if backup_path.exists() {
            fs::remove_file(&backup_path)
                .context(format!("Failed to delete backup file: {:?}", backup_path))?;
            debug!("Deleted backup file: {:?}", backup_path);
        } else {
            warn!("Backup file not found during deletion: {:?}", backup_path);
        }
        
        // Remove metadata
        self.metadata.remove(backup_id);
        self.save_metadata()?;
        
        // Add audit log
        if let Some(user_id) = user_id {
            audit::log_event(
                "BACKUP_DELETED",
                Some(user_id),
                Some(&format!("Deleted backup with ID: {}", backup_id)),
            )?;
        }
        
        info!("Backup {} deleted successfully", backup_id);
        Ok(true)
    }
    
    /// Apply retention policy based on max_backups setting
    fn apply_retention_policy(&mut self) -> Result<()> {
        if self.metadata.len() <= self.max_backups {
            return Ok(());
        }
        
        // Sort backups by creation date
        let mut backups: Vec<(String, DateTime<Utc>)> = self.metadata
            .iter()
            .map(|(id, md)| (id.clone(), md.created_at))
            .collect();
            
        backups.sort_by(|a, b| a.1.cmp(&b.1)); // Oldest first
        
        let to_delete = backups.len() - self.max_backups;
        for i in 0..to_delete {
            let backup_id = &backups[i].0;
            info!("Deleting old backup {} due to retention policy", backup_id);
            
            // Get metadata before deleting
            let metadata = match self.metadata.get(backup_id) {
                Some(md) => md.clone(),
                None => continue,
            };
            
            let backup_path = self.backup_dir.join(&metadata.filename);
            
            if backup_path.exists() {
                if let Err(e) = fs::remove_file(&backup_path) {
                    warn!("Failed to delete old backup file: {:?}: {}", backup_path, e);
                }
            }
            
            // Remove metadata
            self.metadata.remove(backup_id);
        }
        
        // Save updated metadata
        self.save_metadata()?;
        
        debug!("Applied retention policy, deleted {} old backups", to_delete);
        Ok(())
    }
    
    /// Schedule automatic backup
    pub fn schedule_backup(&self) -> Result<()> {
        // This would be implemented with a proper scheduler in a production system
        // For this implementation, we'll just create a backup
        debug!("Scheduled backup triggered");
        
        // Create a new backup manager instance to avoid borrowing issues
        let mut manager = Self::new()?;
        manager.create_backup(Some("Scheduled automatic backup".to_string()), None)?;
        
        Ok(())
    }
    
    /// Implement partial restore for specific data
    pub fn partial_restore(&self, backup_id: &str, tables: &[&str], user_id: Option<&str>) -> Result<()> {
        let metadata = self.metadata.get(backup_id)
            .ok_or_else(|| anyhow!("Backup with ID {} not found", backup_id))?;
            
        let backup_path = self.backup_dir.join(&metadata.filename);
        
        if !backup_path.exists() {
            return Err(anyhow!("Backup file not found: {:?}", backup_path));
        }
        
        let temp_path = self.backup_dir.join("temp_partial_restore.db");
        
        // If the backup is encrypted, decrypt it first
        if metadata.encrypted {
            debug!("Decrypting backup for partial restore");
            self.decrypt_backup(&backup_path, &temp_path)?;
        } else {
            fs::copy(&backup_path, &temp_path)
                .context(format!("Failed to copy backup file for partial restore: {:?}", backup_path))?;
        }
        
        // Open connections to both databases
        let src_conn = Connection::open(&temp_path)
            .context(format!("Failed to open backup database: {:?}", temp_path))?;
            
        let dest_conn = super::get_connection()?;
        
        // Begin transaction
        let tx = dest_conn.transaction()?;
        
        for table in tables {
            info!("Partially restoring table: {}", table);
            
            // Check if table exists in both source and destination
            let src_table_exists: bool = src_conn.query_row(
                &format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{}'", table),
                [],
                |_| Ok(true),
            ).unwrap_or(false);
            
            let dest_table_exists: bool = tx.query_row(
                &format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{}'", table),
                [],
                |_| Ok(true),
            ).unwrap_or(false);
            
            if !src_table_exists {
                warn!("Table {} not found in backup, skipping", table);
                continue;
            }
            
            if !dest_table_exists {
                warn!("Table {} not found in current database, skipping", table);
                continue;
            }
            
            // Get table schema
            let create_stmt: String = src_conn.query_row(
                &format!("SELECT sql FROM sqlite_master WHERE type='table' AND name='{}'", table),
                [],
                |row| row.get(0),
            )?;
            
            // Backup current data
            tx.execute(&format!("CREATE TABLE IF NOT EXISTS temp_{}_backup AS SELECT * FROM {}", table, table), [])?;
            
            // Clear current data
            tx.execute(&format!("DELETE FROM {}", table), [])?;
            
            // Get column names from source
            let mut stmt = src_conn.prepare(&format!("SELECT * FROM {} LIMIT 1", table))?;
            let columns: Vec<String> = stmt.column_names().into_iter().map(|c| c.to_string()).collect();
            
            // Prepare placeholder string for INSERT statements
            let placeholders = columns.iter().map(|_| "?").collect::<Vec<&str>>().join(", ");
            
            // Prepare INSERT statement
            let insert_sql = format!(
                "INSERT INTO {} ({}) VALUES ({})",
                table,
                columns.join(", "),
                placeholders
            );
            
            // Prepare the query to get all rows from source
            let mut src_stmt = src_conn.prepare(&format!("SELECT * FROM {}", table))?;
            let mut rows = src_stmt.query([])?;
            
            // Insert rows into destination
            let mut insert_stmt = tx.prepare(&insert_sql)?;
            let mut row_count = 0;
            
            while let Some(row) = rows.next()? {
                // This is a simplified version - in a real implementation,
                // you would need to handle different data types properly
                let params: Vec<rusqlite::types::Value> = (0..columns.len())
                    .map(|i| row.get_unwrap(i))
                    .collect();
                
                insert_stmt.execute(rusqlite::params_from_iter(params))?;
                row_count += 1;
            }
            
            debug!("Restored {} rows into table {}", row_count, table);
        }
        
        // Commit transaction
        tx.commit()?;
        
        // Clean up temp file
        fs::remove_file(&temp_path).ok();
        
        // Add audit log
        if let Some(user_id) = user_id {
            let tables_str = tables.join(", ");
            audit::log_event(
                "PARTIAL_BACKUP_RESTORED",
                Some(user_id),
                Some(&format!("Partially restored tables [{}] from backup {}", tables_str, backup_id)),
            )?;
        }
        
        info!("Partial restore completed successfully");
        Ok(())
    }
}

// Helper functions for common operations

/// Create a new backup with description
pub fn create_backup(description: Option<String>, user_id: Option<&str>) -> Result<String> {
    let mut manager = BackupManager::new()?;
    manager.create_backup(description, user_id)
}

/// Restore from a backup by ID
pub fn restore_backup(backup_id: &str, user_id: Option<&str>) -> Result<()> {
    let manager = BackupManager::new()?;
    manager.restore_backup(backup_id, user_id)
}

/// List all backups
pub fn list_backups() -> Result<Vec<BackupMetadata>> {
    let manager = BackupManager::new()?;
    Ok(manager.list_backups().into_iter().cloned().collect())
}

/// Verify a backup's integrity
pub fn verify_backup(backup_id: &str) -> Result<bool> {
    let mut manager = BackupManager::new()?;
    manager.verify_backup(backup_id)
}

/// Delete a backup by ID
pub fn delete_backup(backup_id: &str, user_id: Option<&str>) -> Result<bool> {
    let mut manager = BackupManager::new()?;
    manager.delete_backup(backup_id, user_id)
}

/// Schedule automatic backup
pub fn schedule_automatic_backup() -> Result<()> {
    let manager = BackupManager::new()?;
    manager.schedule_backup()
}

/// Perform partial restore for specific tables
pub fn partial_restore(backup_id: &str, tables: &[&str], user_id: Option<&str>) -> Result<()> {
    let manager = BackupManager::new()?;
    manager.partial_restore(backup_id, tables, user_id)
} 