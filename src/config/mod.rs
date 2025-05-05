use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use anyhow::{Result, Context};
use lazy_static::lazy_static;
use std::sync::RwLock;

/// Database configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file
    pub path: String,
    /// Whether to encrypt the database
    pub encrypt: bool,
    /// Key derivation iterations for database encryption
    pub kdf_iterations: Option<u32>,
    /// Maximum number of connections in the connection pool
    pub max_connections: u32,
}

/// Security configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    /// JWT secret key for token signing (in a real app, this should be loaded from a secure source)
    pub jwt_secret: String,
    /// JWT token validity in minutes
    pub token_validity: u64,
    /// Key derivation iterations for password hashing
    pub password_kdf_iterations: u32,
    /// Minimum password length
    pub min_password_length: u8,
    /// Maximum failed login attempts before account lockout
    pub max_failed_attempts: u8,
    /// Account lockout duration in minutes
    pub lockout_duration: u64,
    /// Master password for key encryption (in a real app, this would be securely stored)
    pub master_password: String,
    /// Master salt for key encryption
    pub master_salt: Option<String>,
    /// Path to the encryption key store
    pub key_store_path: String,
    /// Key rotation period in days
    pub key_rotation_days: Option<u64>,
    /// Default encryption algorithm
    pub default_encryption: String,
}

/// Audit configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditConfig {
    /// Path to audit log directory
    pub log_path: String,
    /// Whether to encrypt audit logs
    pub encrypt_logs: bool,
    /// Log retention period in days
    pub retention_days: u32,
}

/// Global application configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Application name
    pub app_name: String,
    /// Application version
    pub version: String,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Audit configuration
    pub audit: AuditConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_name: "Secure Banking CLI".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: DatabaseConfig {
                path: "data/bank.db".to_string(),
                encrypt: true,
                kdf_iterations: Some(10000),
                max_connections: 10,
            },
            security: SecurityConfig {
                jwt_secret: "change_me_in_production".to_string(),
                token_validity: 60, // 60 minutes
                password_kdf_iterations: 10000,
                min_password_length: 12,
                max_failed_attempts: 5,
                lockout_duration: 30, // 30 minutes
                master_password: "change_me_in_production".to_string(),
                master_salt: Some("secure_bank_salt_v1".to_string()),
                key_store_path: "data/keys".to_string(),
                key_rotation_days: Some(90),
                default_encryption: "AES-256-GCM".to_string(),
            },
            audit: AuditConfig {
                log_path: "logs".to_string(),
                encrypt_logs: true,
                retention_days: 90,
            },
        }
    }
}

// Global configuration instance
lazy_static! {
    static ref CONFIG: RwLock<Config> = RwLock::new(Config::default());
}

/// Load configuration from file
pub fn load_config(path: &str) -> Result<()> {
    // Check if file exists
    if !Path::new(path).exists() {
        // If not, create default config and save it
        let default_config = Config::default();
        save_config(path, &default_config)?;
        *CONFIG.write().unwrap() = default_config;
        return Ok(());
    }

    // Read the config file
    let mut file = File::open(path).context(format!("Failed to open config file: {}", path))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).context("Failed to read config file")?;

    // Parse the config file
    let config: Config = match path.ends_with(".toml") {
        true => toml::from_str(&contents).context("Failed to parse TOML config")?,
        false => serde_json::from_str(&contents).context("Failed to parse JSON config")?,
    };

    // Update the global config
    *CONFIG.write().unwrap() = config;

    Ok(())
}

/// Save configuration to file
pub fn save_config(path: &str, config: &Config) -> Result<()> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        }
    }

    // Serialize the config
    let serialized = match path.ends_with(".toml") {
        true => toml::to_string_pretty(config).context("Failed to serialize config to TOML")?,
        false => serde_json::to_string_pretty(config).context("Failed to serialize config to JSON")?,
    };

    // Write to file
    std::fs::write(path, serialized).context(format!("Failed to write config to file: {}", path))?;

    Ok(())
}

/// Get a reference to the current config
pub fn get_config() -> Config {
    CONFIG.read().unwrap().clone()
}

/// Update the current config
pub fn update_config(config: Config) -> Result<()> {
    *CONFIG.write().unwrap() = config;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.app_name, "Secure Banking CLI");
        assert!(config.database.encrypt);
        assert_eq!(config.security.min_password_length, 12);
        assert_eq!(config.security.default_encryption, "AES-256-GCM");
    }

    #[test]
    fn test_load_save_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");
        let config_path_str = config_path.to_str().unwrap();
        
        // Test saving default config
        let config = Config::default();
        save_config(config_path_str, &config).unwrap();
        
        // Test loading saved config
        load_config(config_path_str).unwrap();
        let loaded_config = get_config();
        
        assert_eq!(loaded_config.app_name, config.app_name);
        assert_eq!(loaded_config.database.encrypt, config.database.encrypt);
        assert_eq!(loaded_config.security.min_password_length, config.security.min_password_length);
        assert_eq!(loaded_config.security.key_store_path, config.security.key_store_path);
    }
} 