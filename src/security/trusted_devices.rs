use anyhow::{Result, Context, anyhow};
use log::{debug, info, error};
use rusqlite::{Connection, params};
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use std::fmt;
use uuid::Uuid;

use crate::database::models::AuditEventType;
use crate::security::{generate_secure_token, hash_sha256};

/// Default expiration time for trusted devices (30 days)
pub const TRUSTED_DEVICE_EXPIRY_DAYS: i64 = 30;

/// Maximum number of trusted devices per user
pub const MAX_TRUSTED_DEVICES: usize = 5;

/// Trusted device information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedDevice {
    pub id: String,
    pub user_id: String,
    pub device_name: String,
    pub device_type: String,
    pub last_ip: String,
    pub last_used: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl TrustedDevice {
    pub fn new(
        user_id: String,
        device_name: String,
        device_type: String,
        ip_address: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            device_name,
            device_type,
            last_ip: ip_address,
            last_used: now,
            created_at: now,
            expires_at: now + Duration::days(TRUSTED_DEVICE_EXPIRY_DAYS),
        }
    }
    
    /// Check if the device token has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
    
    /// Update the last used time and IP
    pub fn update_usage(&mut self, ip_address: String) {
        self.last_used = Utc::now();
        self.last_ip = ip_address;
    }
    
    /// Extend the expiration time
    pub fn extend_expiration(&mut self, days: i64) {
        self.expires_at = Utc::now() + Duration::days(days);
    }
}

/// Trusted device errors
#[derive(Debug)]
pub enum TrustedDeviceError {
    /// Database error
    DatabaseError(String),
    /// Device not found
    DeviceNotFound,
    /// Device limit reached
    DeviceLimitReached,
    /// Invalid device token
    InvalidToken,
    /// Device expired
    DeviceExpired,
    /// User not found
    UserNotFound,
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for TrustedDeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustedDeviceError::DatabaseError(err) => write!(f, "Database error: {}", err),
            TrustedDeviceError::DeviceNotFound => write!(f, "Trusted device not found"),
            TrustedDeviceError::DeviceLimitReached => write!(f, "Maximum number of trusted devices reached"),
            TrustedDeviceError::InvalidToken => write!(f, "Invalid device token"),
            TrustedDeviceError::DeviceExpired => write!(f, "Trusted device has expired"),
            TrustedDeviceError::UserNotFound => write!(f, "User not found"),
            TrustedDeviceError::Unknown(err) => write!(f, "Unknown error: {}", err),
        }
    }
}

impl std::error::Error for TrustedDeviceError {}

/// Create a new schema for trusted devices
pub fn create_schema(conn: &mut Connection) -> Result<()> {
    debug!("Creating trusted devices schema");
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS trusted_devices (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            device_type TEXT NOT NULL,
            device_token_hash TEXT NOT NULL,
            last_ip TEXT NOT NULL,
            last_used TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        [],
    ).context("Failed to create trusted_devices table")?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_id ON trusted_devices(user_id)",
        [],
    ).context("Failed to create index on trusted_devices.user_id")?;
    
    debug!("Trusted devices schema created successfully");
    Ok(())
}

/// Add a trusted device for a user
///
/// Returns the device token that should be stored on the client side
pub fn add_trusted_device(
    conn: &Connection,
    user_id: &str,
    device_name: &str,
    device_type: &str,
    ip_address: &str,
) -> Result<String, TrustedDeviceError> {
    debug!("Adding trusted device for user ID: {}", user_id);
    
    // Check if user exists
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM users WHERE id = ?1"
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let user_exists: bool = stmt.query_row(params![user_id], |row| {
        let count: i64 = row.get(0)?;
        Ok(count > 0)
    }).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    if !user_exists {
        return Err(TrustedDeviceError::UserNotFound);
    }
    
    // Check if user has reached the maximum number of trusted devices
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM trusted_devices WHERE user_id = ?1"
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let device_count: i64 = stmt.query_row(params![user_id], |row| {
        row.get(0)
    }).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    if device_count >= MAX_TRUSTED_DEVICES as i64 {
        return Err(TrustedDeviceError::DeviceLimitReached);
    }
    
    // Generate a device token
    let device_token = generate_secure_token();
    let device_token_hash = hash_sha256(&device_token)?;
    
    // Create a new trusted device
    let device = TrustedDevice::new(
        user_id.to_string(),
        device_name.to_string(),
        device_type.to_string(),
        ip_address.to_string(),
    );
    
    // Insert the device into the database
    conn.execute(
        "INSERT INTO trusted_devices (
            id, user_id, device_name, device_type, device_token_hash,
            last_ip, last_used, created_at, expires_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
        )",
        params![
            device.id,
            device.user_id,
            device.device_name,
            device.device_type,
            device_token_hash,
            device.last_ip,
            device.last_used,
            device.created_at,
            device.expires_at
        ]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    // Create audit log entry
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            lower(hex(randomblob(16))),
            ?1, ?2, ?3, ?4
        )",
        params![
            AuditEventType::SecurityEvent.as_str(),
            user_id,
            format!("Added trusted device: {}", device_name),
            Utc::now()
        ]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    info!("Trusted device added for user {}: {}", user_id, device_name);
    Ok(device_token)
}

/// Verify a trusted device token
///
/// Returns true if the device is trusted and not expired
pub fn verify_trusted_device(
    conn: &Connection,
    user_id: &str,
    device_token: &str,
    ip_address: &str,
) -> Result<bool, TrustedDeviceError> {
    debug!("Verifying trusted device for user ID: {}", user_id);
    
    // Hash the device token
    let device_token_hash = hash_sha256(device_token)?;
    
    // Look up the device
    let mut stmt = conn.prepare(
        "SELECT id, expires_at FROM trusted_devices 
         WHERE user_id = ?1 AND device_token_hash = ?2"
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![user_id, device_token_hash], |row| {
        let id: String = row.get(0)?;
        let expires_at: DateTime<Utc> = row.get(1)?;
        Ok((id, expires_at))
    });
    
    let (device_id, expires_at) = match result {
        Ok(data) => data,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Ok(false);
            }
            return Err(TrustedDeviceError::DatabaseError(e.to_string()));
        }
    };
    
    // Check if the device has expired
    if expires_at < Utc::now() {
        // Remove the expired device
        conn.execute(
            "DELETE FROM trusted_devices WHERE id = ?1",
            params![device_id]
        ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
        
        return Ok(false);
    }
    
    // Update the last used time and IP
    conn.execute(
        "UPDATE trusted_devices 
         SET last_used = ?1, last_ip = ?2
         WHERE id = ?3",
        params![Utc::now(), ip_address, device_id]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    debug!("Trusted device verified for user {}", user_id);
    Ok(true)
}

/// Get all trusted devices for a user
pub fn get_trusted_devices(
    conn: &Connection,
    user_id: &str,
) -> Result<Vec<TrustedDevice>, TrustedDeviceError> {
    debug!("Getting trusted devices for user ID: {}", user_id);
    
    let mut stmt = conn.prepare(
        "SELECT id, device_name, device_type, last_ip, last_used, created_at, expires_at
         FROM trusted_devices
         WHERE user_id = ?1
         ORDER BY last_used DESC"
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let devices_iter = stmt.query_map(params![user_id], |row| {
        Ok(TrustedDevice {
            id: row.get(0)?,
            user_id: user_id.to_string(),
            device_name: row.get(1)?,
            device_type: row.get(2)?,
            last_ip: row.get(3)?,
            last_used: row.get(4)?,
            created_at: row.get(5)?,
            expires_at: row.get(6)?,
        })
    }).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let mut devices = Vec::new();
    for device in devices_iter {
        devices.push(device.map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?);
    }
    
    debug!("Found {} trusted devices for user {}", devices.len(), user_id);
    Ok(devices)
}

/// Remove a trusted device
pub fn remove_trusted_device(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
) -> Result<(), TrustedDeviceError> {
    debug!("Removing trusted device {} for user ID: {}", device_id, user_id);
    
    // Check if the device exists and belongs to the user
    let mut stmt = conn.prepare(
        "SELECT device_name FROM trusted_devices WHERE id = ?1 AND user_id = ?2"
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    let result = stmt.query_row(params![device_id, user_id], |row| {
        let device_name: String = row.get(0)?;
        Ok(device_name)
    });
    
    let device_name = match result {
        Ok(name) => name,
        Err(e) => {
            if let rusqlite::Error::QueryReturnedNoRows = e {
                return Err(TrustedDeviceError::DeviceNotFound);
            }
            return Err(TrustedDeviceError::DatabaseError(e.to_string()));
        }
    };
    
    // Delete the device
    conn.execute(
        "DELETE FROM trusted_devices WHERE id = ?1",
        params![device_id]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    // Create audit log entry
    conn.execute(
        "INSERT INTO audit_logs (
            id, event_type, user_id, details, timestamp
        ) VALUES (
            lower(hex(randomblob(16))),
            ?1, ?2, ?3, ?4
        )",
        params![
            AuditEventType::SecurityEvent.as_str(),
            user_id,
            format!("Removed trusted device: {}", device_name),
            Utc::now()
        ]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    info!("Trusted device {} removed for user {}", device_id, user_id);
    Ok(())
}

/// Remove all trusted devices for a user
pub fn remove_all_trusted_devices(
    conn: &Connection,
    user_id: &str,
) -> Result<usize, TrustedDeviceError> {
    debug!("Removing all trusted devices for user ID: {}", user_id);
    
    // Delete all devices
    let deleted = conn.execute(
        "DELETE FROM trusted_devices WHERE user_id = ?1",
        params![user_id]
    ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    
    // Create audit log entry if any devices were deleted
    if deleted > 0 {
        conn.execute(
            "INSERT INTO audit_logs (
                id, event_type, user_id, details, timestamp
            ) VALUES (
                lower(hex(randomblob(16))),
                ?1, ?2, ?3, ?4
            )",
            params![
                AuditEventType::SecurityEvent.as_str(),
                user_id,
                format!("Removed all trusted devices (count: {})", deleted),
                Utc::now()
            ]
        ).map_err(|e| TrustedDeviceError::DatabaseError(e.to_string()))?;
    }
    
    info!("Removed {} trusted devices for user {}", deleted, user_id);
    Ok(deleted as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::database::schema;
    
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        
        let mut conn = Connection::open(&db_path).unwrap();
        schema::create_schema(&mut conn).unwrap();
        create_schema(&mut conn).unwrap();
        
        // Create a test user
        conn.execute(
            "INSERT INTO users (id, username, password_hash, salt, role, created_at, updated_at)
             VALUES ('test-user', 'testuser', 'hash', 'salt', 'user', datetime('now'), datetime('now'))",
            []
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_trusted_device_lifecycle() {
        let (conn, _temp_dir) = setup_test_db();
        
        // Add a trusted device
        let token = add_trusted_device(
            &conn,
            "test-user",
            "My MacBook",
            "desktop",
            "192.168.1.1"
        ).unwrap();
        
        assert!(!token.is_empty());
        
        // Verify the device
        let is_trusted = verify_trusted_device(
            &conn,
            "test-user",
            &token,
            "192.168.1.2"
        ).unwrap();
        
        assert!(is_trusted);
        
        // Get trusted devices
        let devices = get_trusted_devices(&conn, "test-user").unwrap();
        
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_name, "My MacBook");
        assert_eq!(devices[0].device_type, "desktop");
        assert_eq!(devices[0].last_ip, "192.168.1.2"); // Should be updated from verification
        
        // Remove the device
        remove_trusted_device(&conn, "test-user", &devices[0].id).unwrap();
        
        // Verify device is gone
        let devices = get_trusted_devices(&conn, "test-user").unwrap();
        assert_eq!(devices.len(), 0);
    }
} 