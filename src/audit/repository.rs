use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use log::{debug, error};
use rusqlite::{params, Connection, Transaction};
use std::collections::HashMap;

use crate::database::models::{AuditEventType, AuditLog};
use crate::database::get_connection;
use crate::security::encryption;

/// Repository for audit operations
pub struct AuditRepository;

impl AuditRepository {
    /// Save an audit log to the database
    pub fn save_audit_log(audit_log: &AuditLog) -> Result<()> {
        let conn = get_connection()?;
        
        conn.execute(
            "INSERT INTO audit_logs (
                id, event_type, user_id, account_id, transaction_id, 
                ip_address, details, encrypted_details, timestamp
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
            )",
            params![
                audit_log.id,
                audit_log.event_type.as_str(),
                audit_log.user_id,
                audit_log.account_id,
                audit_log.transaction_id,
                audit_log.ip_address,
                audit_log.details,
                audit_log.encrypted_details,
                audit_log.timestamp.to_rfc3339()
            ],
        ).context("Failed to insert audit log")?;
        
        debug!("Saved audit log with ID: {}", audit_log.id);
        Ok(())
    }
    
    /// Get audit logs by user ID
    pub fn get_audit_logs_by_user(user_id: &str, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<AuditLog>> {
        let conn = get_connection()?;
        
        let limit_value = limit.unwrap_or(100);
        let offset_value = offset.unwrap_or(0);
        
        let mut stmt = conn.prepare(
            "SELECT id, event_type, user_id, account_id, transaction_id, 
                    ip_address, details, encrypted_details, timestamp
             FROM audit_logs
             WHERE user_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2 OFFSET ?3"
        ).context("Failed to prepare statement for getting audit logs by user")?;
        
        let logs = stmt.query_map(
            params![user_id, limit_value as i64, offset_value as i64],
            |row| {
                let timestamp_str: String = row.get(8)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                
                Ok(AuditLog {
                    id: row.get(0)?,
                    event_type: AuditEventType::from_str(&row.get::<_, String>(1)?).unwrap_or(AuditEventType::SecurityEvent),
                    user_id: row.get(2)?,
                    account_id: row.get(3)?,
                    transaction_id: row.get(4)?,
                    ip_address: row.get(5)?,
                    details: row.get(6)?,
                    encrypted_details: row.get(7)?,
                    timestamp,
                })
            },
        ).context("Failed to query audit logs by user")?;
        
        let mut result = Vec::new();
        for log in logs {
            result.push(log.context("Failed to process audit log row")?);
        }
        
        Ok(result)
    }
    
    /// Get audit logs by account ID
    pub fn get_audit_logs_by_account(account_id: &str, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<AuditLog>> {
        let conn = get_connection()?;
        
        let limit_value = limit.unwrap_or(100);
        let offset_value = offset.unwrap_or(0);
        
        let mut stmt = conn.prepare(
            "SELECT id, event_type, user_id, account_id, transaction_id, 
                    ip_address, details, encrypted_details, timestamp
             FROM audit_logs
             WHERE account_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2 OFFSET ?3"
        ).context("Failed to prepare statement for getting audit logs by account")?;
        
        let logs = stmt.query_map(
            params![account_id, limit_value as i64, offset_value as i64],
            |row| {
                let timestamp_str: String = row.get(8)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                
                Ok(AuditLog {
                    id: row.get(0)?,
                    event_type: AuditEventType::from_str(&row.get::<_, String>(1)?).unwrap_or(AuditEventType::SecurityEvent),
                    user_id: row.get(2)?,
                    account_id: row.get(3)?,
                    transaction_id: row.get(4)?,
                    ip_address: row.get(5)?,
                    details: row.get(6)?,
                    encrypted_details: row.get(7)?,
                    timestamp,
                })
            },
        ).context("Failed to query audit logs by account")?;
        
        let mut result = Vec::new();
        for log in logs {
            result.push(log.context("Failed to process audit log row")?);
        }
        
        Ok(result)
    }
    
    /// Get audit logs by event type
    pub fn get_audit_logs_by_event_type(event_type: AuditEventType, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<AuditLog>> {
        let conn = get_connection()?;
        
        let limit_value = limit.unwrap_or(100);
        let offset_value = offset.unwrap_or(0);
        
        let mut stmt = conn.prepare(
            "SELECT id, event_type, user_id, account_id, transaction_id, 
                    ip_address, details, encrypted_details, timestamp
             FROM audit_logs
             WHERE event_type = ?1
             ORDER BY timestamp DESC
             LIMIT ?2 OFFSET ?3"
        ).context("Failed to prepare statement for getting audit logs by event type")?;
        
        let logs = stmt.query_map(
            params![event_type.as_str(), limit_value as i64, offset_value as i64],
            |row| {
                let timestamp_str: String = row.get(8)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                
                Ok(AuditLog {
                    id: row.get(0)?,
                    event_type: AuditEventType::from_str(&row.get::<_, String>(1)?).unwrap_or(AuditEventType::SecurityEvent),
                    user_id: row.get(2)?,
                    account_id: row.get(3)?,
                    transaction_id: row.get(4)?,
                    ip_address: row.get(5)?,
                    details: row.get(6)?,
                    encrypted_details: row.get(7)?,
                    timestamp,
                })
            },
        ).context("Failed to query audit logs by event type")?;
        
        let mut result = Vec::new();
        for log in logs {
            result.push(log.context("Failed to process audit log row")?);
        }
        
        Ok(result)
    }
    
    /// Search audit logs with filtering
    pub fn search_audit_logs(
        filters: HashMap<String, String>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: Option<usize>,
        offset: Option<usize>
    ) -> Result<Vec<AuditLog>> {
        let conn = get_connection()?;
        
        let limit_value = limit.unwrap_or(100);
        let offset_value = offset.unwrap_or(0);
        
        // Build the query dynamically based on filters
        let mut query = String::from(
            "SELECT id, event_type, user_id, account_id, transaction_id, 
                    ip_address, details, encrypted_details, timestamp
             FROM audit_logs
             WHERE 1=1"
        );
        
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        
        // Add filters to query
        if let Some(user_id) = filters.get("user_id") {
            query.push_str(" AND user_id = ?");
            params.push(Box::new(user_id.clone()));
        }
        
        if let Some(account_id) = filters.get("account_id") {
            query.push_str(" AND account_id = ?");
            params.push(Box::new(account_id.clone()));
        }
        
        if let Some(transaction_id) = filters.get("transaction_id") {
            query.push_str(" AND transaction_id = ?");
            params.push(Box::new(transaction_id.clone()));
        }
        
        if let Some(event_type) = filters.get("event_type") {
            query.push_str(" AND event_type = ?");
            params.push(Box::new(event_type.clone()));
        }
        
        if let Some(ip_address) = filters.get("ip_address") {
            query.push_str(" AND ip_address = ?");
            params.push(Box::new(ip_address.clone()));
        }
        
        // Add date range if specified
        if let Some(from) = date_from {
            query.push_str(" AND timestamp >= ?");
            params.push(Box::new(from.to_rfc3339()));
        }
        
        if let Some(to) = date_to {
            query.push_str(" AND timestamp <= ?");
            params.push(Box::new(to.to_rfc3339()));
        }
        
        // Add details search if specified
        if let Some(details_search) = filters.get("details_search") {
            query.push_str(" AND details LIKE ?");
            params.push(Box::new(format!("%{}%", details_search)));
        }
        
        // Add order by and limit
        query.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.push(Box::new(limit_value as i64));
        params.push(Box::new(offset_value as i64));
        
        // Prepare statement with the dynamic query
        let mut stmt = conn.prepare(&query)
            .context("Failed to prepare statement for searching audit logs")?;
        
        // Convert params to a slice of references
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter()
            .map(|p| p.as_ref() as &dyn rusqlite::ToSql)
            .collect();
        
        let logs = stmt.query_map(
            rusqlite::params_from_iter(param_refs.iter()),
            |row| {
                let timestamp_str: String = row.get(8)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                
                Ok(AuditLog {
                    id: row.get(0)?,
                    event_type: AuditEventType::from_str(&row.get::<_, String>(1)?).unwrap_or(AuditEventType::SecurityEvent),
                    user_id: row.get(2)?,
                    account_id: row.get(3)?,
                    transaction_id: row.get(4)?,
                    ip_address: row.get(5)?,
                    details: row.get(6)?,
                    encrypted_details: row.get(7)?,
                    timestamp,
                })
            },
        ).context("Failed to query audit logs with filters")?;
        
        let mut result = Vec::new();
        for log in logs {
            result.push(log.context("Failed to process audit log row")?);
        }
        
        Ok(result)
    }
    
    /// Clear old audit logs based on retention policy
    pub fn clear_old_audit_logs(retention_days: u32) -> Result<usize> {
        let conn = get_connection()?;
        
        // Calculate cutoff date
        let now = Utc::now();
        let cutoff_date = now - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff_date.to_rfc3339();
        
        // Delete old logs
        let deleted_count = conn.execute(
            "DELETE FROM audit_logs WHERE timestamp < ?1",
            params![cutoff_str],
        ).context("Failed to delete old audit logs")?;
        
        debug!("Cleared {} audit logs older than {} days", deleted_count, retention_days);
        Ok(deleted_count)
    }
    
    /// Encrypt sensitive information in audit logs
    pub fn encrypt_sensitive_logs(tx: &Transaction) -> Result<usize> {
        // Find unencrypted logs that contain sensitive information
        let mut stmt = tx.prepare(
            "SELECT id, details FROM audit_logs 
             WHERE encrypted_details IS NULL 
             AND details IS NOT NULL 
             AND (
                 details LIKE '%password%' OR 
                 details LIKE '%credentials%' OR 
                 details LIKE '%credit_card%' OR
                 details LIKE '%ssn%' OR
                 details LIKE '%social_security%' OR
                 details LIKE '%account_number%'
             )"
        ).context("Failed to prepare statement for finding sensitive logs")?;
        
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).context("Failed to query sensitive logs")?;
        
        let mut count = 0;
        for row in rows {
            let (id, details) = row.context("Failed to process sensitive log row")?;
            
            // Encrypt the sensitive details
            match encryption::encrypt_sensitive_data(&details) {
                Ok(encrypted) => {
                    // Update the log with encrypted details
                    tx.execute(
                        "UPDATE audit_logs SET encrypted_details = ?1, details = '[REDACTED]' WHERE id = ?2",
                        params![encrypted, id],
                    ).context("Failed to update audit log with encrypted details")?;
                    count += 1;
                },
                Err(e) => {
                    error!("Failed to encrypt sensitive audit log {}: {}", id, e);
                }
            }
        }
        
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema;
    use rusqlite::Connection;
    use tempfile::TempDir;
    
    // Helper function to create a test database
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_audit.db");
        
        let conn = Connection::open(&db_path).unwrap();
        schema::create_schema(&conn).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_save_and_retrieve_audit_log() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Create a test audit log
        let audit_log = AuditLog {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: AuditEventType::UserLogin,
            user_id: Some("test_user".to_string()),
            account_id: None,
            transaction_id: None,
            ip_address: Some("127.0.0.1".to_string()),
            details: Some("Test login".to_string()),
            encrypted_details: None,
            timestamp: Utc::now(),
        };
        
        // Insert directly using the connection
        conn.execute(
            "INSERT INTO audit_logs (
                id, event_type, user_id, ip_address, details, timestamp
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6
            )",
            params![
                audit_log.id,
                audit_log.event_type.as_str(),
                audit_log.user_id,
                audit_log.ip_address,
                audit_log.details,
                audit_log.timestamp.to_rfc3339()
            ],
        ).unwrap();
        
        // Query by user ID
        let mut stmt = conn.prepare(
            "SELECT id, event_type, user_id, ip_address, details, timestamp
             FROM audit_logs
             WHERE user_id = ?"
        ).unwrap();
        
        let logs = stmt.query_map(
            params!["test_user"],
            |row| {
                let timestamp_str: String = row.get(5)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                
                Ok(AuditLog {
                    id: row.get(0)?,
                    event_type: AuditEventType::from_str(&row.get::<_, String>(1)?).unwrap(),
                    user_id: row.get(2)?,
                    account_id: None,
                    transaction_id: None,
                    ip_address: row.get(3)?,
                    details: row.get(4)?,
                    encrypted_details: None,
                    timestamp,
                })
            },
        ).unwrap();
        
        let result: Vec<AuditLog> = logs.map(|r| r.unwrap()).collect();
        
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, audit_log.id);
        assert_eq!(result[0].event_type, AuditEventType::UserLogin);
        assert_eq!(result[0].user_id, Some("test_user".to_string()));
        assert_eq!(result[0].details, Some("Test login".to_string()));
    }
} 