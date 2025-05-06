use anyhow::{Result, Context};
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{debug, error, info, warn};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::config;
use crate::security::encryption;

/// Manages log file rotation and archiving
pub struct LogArchiver {
    log_path: PathBuf,
    archive_path: PathBuf,
    max_log_size: usize,
    retention_days: u32,
}

impl LogArchiver {
    /// Create a new log archiver
    pub fn new() -> Result<Self> {
        let config = config::get_config();
        
        let log_path = PathBuf::from(&config.audit.log_path);
        if !log_path.exists() {
            fs::create_dir_all(&log_path).context("Failed to create audit log directory")?;
        }
        
        // Create archive directory inside log path if it doesn't exist
        let archive_path = log_path.join("archives");
        if !archive_path.exists() {
            fs::create_dir_all(&archive_path).context("Failed to create log archive directory")?;
        }
        
        // Default max log size: 10MB
        let max_log_size = 10 * 1024 * 1024;
        
        Ok(Self {
            log_path,
            archive_path,
            max_log_size,
            retention_days: config.audit.retention_days,
        })
    }
    
    /// Check if any log files need rotation and rotate them
    pub fn check_and_rotate_logs(&self) -> Result<usize> {
        let mut rotated_count = 0;
        
        // Read all log files from the log directory
        let log_files = fs::read_dir(&self.log_path)
            .context("Failed to read log directory")?
            .filter_map(Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.is_file() && 
                path.extension().map_or(false, |ext| ext == "log") &&
                !path.starts_with(&self.archive_path)
            });
        
        for entry in log_files {
            let path = entry.path();
            let metadata = fs::metadata(&path).context("Failed to get log file metadata")?;
            
            // Check if file size exceeds max size
            if metadata.len() as usize > self.max_log_size {
                self.rotate_log_file(&path)?;
                rotated_count += 1;
            }
        }
        
        info!("Rotated {} log files", rotated_count);
        Ok(rotated_count)
    }
    
    /// Rotate a specific log file
    fn rotate_log_file(&self, log_path: &Path) -> Result<()> {
        let file_name = log_path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid log file name"))?;
        
        // Generate archive file name with timestamp
        let now = Utc::now();
        let timestamp = now.format("%Y%m%d%H%M%S");
        let archive_name = format!("{}.{}.gz", file_name, timestamp);
        let archive_path = self.archive_path.join(archive_name);
        
        // Read the log file content
        let mut content = Vec::new();
        let mut file = File::open(log_path).context("Failed to open log file for rotation")?;
        file.read_to_end(&mut content).context("Failed to read log file content")?;
        
        // Compress the content with gzip
        let compressed = self.compress_data(&content)?;
        
        // Write to archive file
        fs::write(&archive_path, compressed).context("Failed to write compressed log to archive")?;
        
        // Truncate the original log file
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(log_path)
            .context("Failed to truncate log file after rotation")?;
        
        // Write a rotation marker to the beginning of the new log file
        let rotation_marker = format!(
            "# Log rotated at {} - previous log archived to {}\n",
            now.to_rfc3339(),
            archive_path.file_name().unwrap_or_default().to_string_lossy()
        );
        file.write_all(rotation_marker.as_bytes()).context("Failed to write rotation marker")?;
        
        debug!("Rotated log file {} to archive {}", 
               log_path.display(), 
               archive_path.display());
        
        Ok(())
    }
    
    /// Compress data using gzip
    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::prelude::*;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).context("Failed to compress log data")?;
        encoder.finish().context("Failed to finish compressing log data")
    }
    
    /// Prune old archive files based on retention policy
    pub fn prune_old_archives(&self) -> Result<usize> {
        let mut deleted_count = 0;
        
        // Calculate the cutoff date
        let now = Utc::now();
        let cutoff = now - Duration::days(self.retention_days as i64);
        
        // Read all files from archive directory
        if !self.archive_path.exists() {
            return Ok(0); // No archives directory yet
        }
        
        let archive_files = fs::read_dir(&self.archive_path)
            .context("Failed to read archive directory")?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file());
        
        for entry in archive_files {
            let path = entry.path();
            
            // Parse the timestamp from filename (format: filename.YYYYMMDDHHMMSS.gz)
            if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                if let Some(timestamp_str) = file_name.split('.').nth(1) {
                    // Parse the timestamp
                    if let Ok(timestamp) = Self::parse_timestamp_from_filename(timestamp_str) {
                        // Check if the file is older than the retention period
                        if timestamp < cutoff {
                            // Delete the file
                            if let Err(e) = fs::remove_file(&path) {
                                warn!("Failed to delete old archive file {}: {}", path.display(), e);
                            } else {
                                deleted_count += 1;
                                debug!("Deleted old archive file: {}", path.display());
                            }
                        }
                    }
                }
            }
        }
        
        info!("Pruned {} old archive files", deleted_count);
        Ok(deleted_count)
    }
    
    /// Parse timestamp from filename format YYYYMMDDHHMMSS
    fn parse_timestamp_from_filename(timestamp_str: &str) -> Result<DateTime<Utc>> {
        if timestamp_str.len() != 14 {
            return Err(anyhow::anyhow!("Invalid timestamp format, expected YYYYMMDDHHMMSS"));
        }
        
        let year = timestamp_str[0..4].parse::<i32>()
            .context("Failed to parse year from timestamp")?;
        let month = timestamp_str[4..6].parse::<u32>()
            .context("Failed to parse month from timestamp")?;
        let day = timestamp_str[6..8].parse::<u32>()
            .context("Failed to parse day from timestamp")?;
        let hour = timestamp_str[8..10].parse::<u32>()
            .context("Failed to parse hour from timestamp")?;
        let minute = timestamp_str[10..12].parse::<u32>()
            .context("Failed to parse minute from timestamp")?;
        let second = timestamp_str[12..14].parse::<u32>()
            .context("Failed to parse second from timestamp")?;
        
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .earliest()
            .ok_or_else(|| anyhow::anyhow!("Invalid timestamp"))
    }
    
    /// Encrypt an archive file
    pub fn encrypt_archive(&self, archive_path: &Path) -> Result<PathBuf> {
        // Check if the config says to encrypt logs
        let config = config::get_config();
        if !config.audit.encrypt_logs {
            return Ok(archive_path.to_path_buf());
        }
        
        // Read the archive file
        let content = fs::read(archive_path).context("Failed to read archive file for encryption")?;
        
        // Encrypt the content
        let encrypted = encryption::encrypt_data(&content)?;
        
        // Create encrypted file path (add .enc extension)
        let encrypted_path = archive_path.with_extension("enc");
        
        // Write encrypted content
        fs::write(&encrypted_path, encrypted).context("Failed to write encrypted archive")?;
        
        // Delete the original unencrypted archive
        fs::remove_file(archive_path).context("Failed to delete unencrypted archive after encryption")?;
        
        info!("Encrypted archive {} to {}", 
             archive_path.display(), 
             encrypted_path.display());
        
        Ok(encrypted_path)
    }
    
    /// Decrypt an encrypted archive file
    pub fn decrypt_archive(&self, encrypted_path: &Path, output_path: Option<&Path>) -> Result<PathBuf> {
        // Verify the file has .enc extension
        if encrypted_path.extension().map_or(true, |ext| ext != "enc") {
            return Err(anyhow::anyhow!("File does not have .enc extension"));
        }
        
        // Read the encrypted file
        let encrypted_content = fs::read(encrypted_path)
            .context("Failed to read encrypted archive")?;
        
        // Decrypt the content
        let decrypted = encryption::decrypt_data(&encrypted_content)?;
        
        // Determine output path
        let output = match output_path {
            Some(path) => path.to_path_buf(),
            None => {
                // Default: remove .enc extension
                let file_stem = encrypted_path.file_stem()
                    .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
                encrypted_path.with_file_name(file_stem)
            }
        };
        
        // Write decrypted content
        fs::write(&output, decrypted).context("Failed to write decrypted archive")?;
        
        info!("Decrypted archive {} to {}", 
             encrypted_path.display(), 
             output.display());
        
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};
    
    // Helper function to create test log archiver
    fn create_test_archiver() -> (LogArchiver, TempDir) {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("logs");
        let archive_path = log_path.join("archives");
        
        fs::create_dir_all(&log_path).unwrap();
        fs::create_dir_all(&archive_path).unwrap();
        
        let archiver = LogArchiver {
            log_path,
            archive_path,
            max_log_size: 1024, // 1KB for testing
            retention_days: 30,
        };
        
        (archiver, temp_dir)
    }
    
    #[test]
    fn test_parse_timestamp_from_filename() {
        let timestamp_str = "20230415123045";
        let parsed = LogArchiver::parse_timestamp_from_filename(timestamp_str).unwrap();
        
        assert_eq!(parsed.year(), 2023);
        assert_eq!(parsed.month(), 4);
        assert_eq!(parsed.day(), 15);
        assert_eq!(parsed.hour(), 12);
        assert_eq!(parsed.minute(), 30);
        assert_eq!(parsed.second(), 45);
    }
    
    #[test]
    fn test_log_rotation() {
        let (archiver, _temp_dir) = create_test_archiver();
        
        // Create a test log file
        let log_file_path = archiver.log_path.join("test.log");
        let content = "x".repeat(2048); // 2KB, larger than the max_log_size
        fs::write(&log_file_path, &content).unwrap();
        
        // Rotate the log
        archiver.rotate_log_file(&log_file_path).unwrap();
        
        // Check that the archive directory has a file
        let archive_files: Vec<_> = fs::read_dir(&archiver.archive_path)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        
        assert_eq!(archive_files.len(), 1);
        
        // Check that the original log file was truncated
        let new_size = fs::metadata(&log_file_path).unwrap().len();
        assert!(new_size < 2048);
    }
} 