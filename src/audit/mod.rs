use anyhow::{Result, Context};
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::config;
use crate::database::models::AuditEventType;
use crate::security;

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
        // TODO: Implement saving to database
        // This would use the database module to insert the audit event
        // into the audit_logs table
        
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
    
    /// Verify audit log integrity
    pub fn verify_log_integrity(&self, file_path: &str) -> Result<bool> {
        // In a real implementation, this would use cryptographic techniques
        // to verify the integrity of the audit log file, such as a hash chain
        // or digital signatures
        
        // TODO: Implement audit log integrity verification
        
        warn!("Audit log integrity verification not fully implemented");
        Ok(true)
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
        ).unwrap();
        
        assert!(!event_id.is_empty());
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
        let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.event_type.as_str(), deserialized.event_type.as_str());
    }
} 