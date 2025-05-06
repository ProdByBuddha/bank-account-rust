use anyhow::{Result, Context};
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::config;
use crate::database::models::{AuditEventType, AuditLog};
use crate::security;

// Import submodules
pub mod repository;
pub mod archiver;
pub mod compliance;

use repository::AuditRepository;
use archiver::LogArchiver;

/// Audit logger
pub struct AuditLogger {
    log_path: String,
    encrypt_logs: bool,
    encryption_key: Option<[u8; 32]>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new() -> Result<Self> {
        let config = config::get_config();
        
        // Create log directory if it doesn't exist
        let log_path = config.audit.log_path.clone();
        if !Path::new(&log_path).exists() {
            fs::create_dir_all(&log_path).context("Failed to create audit log directory")?;
        }
        
        // TODO: In a real application, encryption keys would be securely managed
        // This is just a placeholder
        let encryption_key = if config.audit.encrypt_logs {
            Some(security::generate_encryption_key())
        } else {
            None
        };
        
        Ok(Self {
            log_path,
            encrypt_logs: config.audit.encrypt_logs,
            encryption_key,
        })
    }
    
    /// Log an audit event
    pub fn log_event(
        &self,
        event_type: AuditEventType,
        user_id: Option<&str>,
        account_id: Option<&str>,
        transaction_id: Option<&str>,
        ip_address: Option<&str>,
        details: Option<&str>,
    ) -> Result<String> {
        let event_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        
        // Create audit event
        let event = AuditEvent {
            id: event_id.clone(),
            event_type,
            user_id: user_id.map(|s| s.to_string()),
            account_id: account_id.map(|s| s.to_string()),
            transaction_id: transaction_id.map(|s| s.to_string()),
            ip_address: ip_address.map(|s| s.to_string()),
            details: details.map(|s| s.to_string()),
            timestamp,
        };
        
        // Save to database
        self.save_to_database(&event)?;
        
        // Save to file
        self.save_to_file(&event)?;
        
        info!("Audit event logged: {} - {}", event_id, event_type.as_str());
        Ok(event_id)
    }
    
    /// Save audit event to database
    fn save_to_database(&self, event: &AuditEvent) -> Result<()> {
        // Convert AuditEvent to AuditLog
        let audit_log = AuditLog {
            id: event.id.clone(),
            event_type: event.event_type,
            user_id: event.user_id.clone(),
            account_id: event.account_id.clone(),
            transaction_id: event.transaction_id.clone(),
            ip_address: event.ip_address.clone(),
            details: event.details.clone(),
            encrypted_details: None, // Will be handled by the repository if needed
            timestamp: event.timestamp,
        };
        
        // Use the repository to save to database
        AuditRepository::save_audit_log(&audit_log)?;
        
        Ok(())
    }
    
    /// Save audit event to file
    fn save_to_file(&self, event: &AuditEvent) -> Result<()> {
        let file_path = format!("{}/audit_{}.log", self.log_path, 
            Utc::now().format("%Y%m%d"));
        
        // Serialize the event
        let serialized = serde_json::to_string(&event)
            .context("Failed to serialize audit event")?;
        
        // Encrypt if needed
        let log_entry = if self.encrypt_logs {
            if let Some(key) = self.encryption_key {
                let encrypted = security::encrypt_string(&serialized, &key)
                    .context("Failed to encrypt audit event")?;
                format!("{}\n", encrypted)
            } else {
                return Err(anyhow::anyhow!("Encryption key not available"));
            }
        } else {
            format!("{}\n", serialized)
        };
        
        // Open file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .context(format!("Failed to open audit log file: {}", file_path))?;
        
        // Write log entry
        file.write_all(log_entry.as_bytes())
            .context("Failed to write to audit log file")?;
        
        debug!("Audit event saved to file: {}", file_path);
        Ok(())
    }
    
    /// Search audit logs with filtering
    pub fn search_logs(
        &self,
        user_id: Option<&str>,
        account_id: Option<&str>,
        event_type: Option<AuditEventType>,
        from_date: Option<DateTime<Utc>>,
        to_date: Option<DateTime<Utc>>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<AuditLog>> {
        let mut filters = std::collections::HashMap::new();
        
        if let Some(user) = user_id {
            filters.insert("user_id".to_string(), user.to_string());
        }
        
        if let Some(account) = account_id {
            filters.insert("account_id".to_string(), account.to_string());
        }
        
        if let Some(event) = event_type {
            filters.insert("event_type".to_string(), event.as_str().to_string());
        }
        
        AuditRepository::search_audit_logs(filters, from_date, to_date, limit, offset)
    }
    
    /// Perform log rotation if needed
    pub fn check_log_rotation(&self) -> Result<()> {
        let archiver = LogArchiver::new()?;
        let rotated = archiver.check_and_rotate_logs()?;
        
        if rotated > 0 {
            info!("Rotated {} log files", rotated);
        }
        
        // Also prune old archives
        let pruned = archiver.prune_old_archives()?;
        if pruned > 0 {
            info!("Pruned {} old archive files", pruned);
        }
        
        Ok(())
    }
    
    /// Verify audit log integrity
    pub fn verify_log_integrity(&self, file_path: &str) -> Result<bool> {
        // In a real implementation, this would use cryptographic techniques
        // to verify the integrity of the audit log file, such as a hash chain
        // or digital signatures
        
        // For now, just check if the file exists and is readable
        if !Path::new(file_path).exists() {
            return Err(anyhow::anyhow!("Audit log file does not exist"));
        }
        
        match fs::metadata(file_path) {
            Ok(metadata) => {
                if metadata.is_file() && metadata.len() > 0 {
                    // In a real implementation, we would validate hash chains here
                    warn!("Audit log integrity verification not fully implemented");
                    Ok(true)
                } else {
                    Err(anyhow::anyhow!("Invalid audit log file"))
                }
            },
            Err(e) => Err(anyhow::anyhow!("Failed to read audit log file: {}", e)),
        }
    }
    
    /// Decrypt an encrypted audit log file
    pub fn decrypt_log_file(&self, file_path: &str, output_path: &str) -> Result<()> {
        if !self.encrypt_logs || self.encryption_key.is_none() {
            return Err(anyhow::anyhow!("Encryption not enabled or key not available"));
        }
        
        let key = self.encryption_key.unwrap();
        
        // Read encrypted file
        let contents = fs::read_to_string(file_path)
            .context(format!("Failed to read encrypted log file: {}", file_path))?;
        
        // Open output file
        let mut output_file = File::create(output_path)
            .context(format!("Failed to create output file: {}", output_path))?;
        
        // Process each line
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            // Decrypt line
            let decrypted = security::decrypt_string(line, &key)
                .context("Failed to decrypt audit log entry")?;
            
            // Write to output file
            output_file.write_all(format!("{}\n", decrypted).as_bytes())
                .context("Failed to write to decrypted log file")?;
        }
        
        info!("Decrypted audit log saved to: {}", output_path);
        Ok(())
    }
    
    /// Encrypt sensitive information in existing logs
    pub fn encrypt_sensitive_logs(&self) -> Result<usize> {
        // Get database connection and start a transaction
        let conn = crate::database::get_connection()?;
        let tx = conn.transaction()?;
        
        // Encrypt sensitive logs
        let count = AuditRepository::encrypt_sensitive_logs(&tx)?;
        
        // Commit the transaction
        tx.commit()?;
        
        info!("Encrypted sensitive information in {} audit logs", count);
        Ok(count)
    }
    
    /// Clean up old audit logs based on retention policy
    pub fn clean_old_logs(&self) -> Result<usize> {
        let config = config::get_config();
        let count = AuditRepository::clear_old_audit_logs(config.audit.retention_days)?;
        info!("Cleaned {} old audit logs", count);
        Ok(count)
    }
    
    /// Get recent audit events for a user
    pub fn get_recent_user_events(&self, user_id: &str, limit: Option<usize>) -> Result<Vec<AuditLog>> {
        AuditRepository::get_audit_logs_by_user(user_id, limit, None)
    }
    
    /// Get recent audit events for an account
    pub fn get_recent_account_events(&self, account_id: &str, limit: Option<usize>) -> Result<Vec<AuditLog>> {
        AuditRepository::get_audit_logs_by_account(account_id, limit, None)
    }
    
    /// Get recent audit events by type
    pub fn get_recent_events_by_type(&self, event_type: AuditEventType, limit: Option<usize>) -> Result<Vec<AuditLog>> {
        AuditRepository::get_audit_logs_by_event_type(event_type, limit, None)
    }
    
    /// Check for suspicious activity patterns
    pub fn check_suspicious_activity(&self, user_id: &str) -> Result<Vec<AuditLog>> {
        // This is a simplified version. In a real system, we would use more
        // sophisticated algorithms to detect suspicious patterns.
        let suspicious_events = vec![
            AuditEventType::UserLoginFailed,
            AuditEventType::UserLocked,
            AuditEventType::SecurityEvent,
            AuditEventType::BackupCodeUsed,
        ];
        
        let mut results = Vec::new();
        
        // Get recent activity for the user
        let recent_logs = self.get_recent_user_events(user_id, Some(100))?;
        
        // Filter for suspicious events
        for log in recent_logs {
            if suspicious_events.contains(&log.event_type) {
                results.push(log);
            }
        }
        
        Ok(results)
    }
}

/// Audit event
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub id: String,
    #[serde(with = "audit_event_type_ser_de")]
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub transaction_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// Custom serialization/deserialization for AuditEventType
mod audit_event_type_ser_de {
    use super::*;
    use serde::{Serializer, Deserializer};
    use serde::de::{self, Visitor};
    use std::fmt;
    
    pub fn serialize<S>(event_type: &AuditEventType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(event_type.as_str())
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<AuditEventType, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuditEventTypeVisitor;
        
        impl<'de> Visitor<'de> for AuditEventTypeVisitor {
            type Value = AuditEventType;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing an audit event type")
            }
            
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                AuditEventType::from_str(value).map_err(|e| de::Error::custom(e))
            }
        }
        
        deserializer.deserialize_str(AuditEventTypeVisitor)
    }
}

// Schedule periodic audit maintenance tasks
pub fn schedule_audit_maintenance() -> Result<()> {
    // In a real application, this would set up scheduled tasks or a background thread
    // For this example, we'll just log a message
    info!("Audit maintenance tasks scheduled");
    
    // These tasks would typically run on a schedule:
    // 1. Log rotation check
    // 2. Cleanup of old logs based on retention policy
    // 3. Encryption of sensitive information
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};
    
    // Helper function to create a test audit logger
    fn create_test_logger() -> (AuditLogger, TempDir) {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().to_str().unwrap().to_string();
        
        let logger = AuditLogger {
            log_path,
            encrypt_logs: false,
            encryption_key: None,
        };
        
        (logger, temp_dir)
    }
    
    #[test]
    fn test_log_event_unencrypted() {
        let (logger, _temp_dir) = create_test_logger();
        
        let event_id = logger.log_event(
            AuditEventType::UserLogin,
            Some("test_user"),
            None,
            None,
            Some("127.0.0.1"),
            Some("Test login event"),
        );
        
        assert!(event_id.is_ok());
    }
    
    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type: AuditEventType::UserLogin,
            user_id: Some("test_user".to_string()),
            account_id: None,
            transaction_id: None,
            ip_address: Some("127.0.0.1".to_string()),
            details: Some("Test login event".to_string()),
            timestamp: Utc::now(),
        };
        
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("UserLogin"));
        assert!(serialized.contains("test_user"));
        
        let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.event_type, AuditEventType::UserLogin);
        assert_eq!(deserialized.user_id, Some("test_user".to_string()));
    }
} 