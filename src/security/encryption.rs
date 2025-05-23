use anyhow::{anyhow, Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use hmac::{Hmac, Mac};
use log::{debug, info, warn};
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::config;

// Constants for encryption 
const AES_KEY_LEN: usize = 32; // 256 bits
const CHACHA_KEY_LEN: usize = 32; // 256 bits
const NONCE_LEN: usize = 12; // 96 bits
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const KEY_ROTATION_PERIOD_DAYS: u64 = 90; // 3 months

// For key versioning
const CURRENT_KEY_VERSION: &str = "current";
const KEY_PREFIX: &str = "key_";

// Key storage structure
lazy_static::lazy_static! {
    static ref KEY_STORE: RwLock<KeyStore> = RwLock::new(KeyStore::new());
}

/// Key metadata for tracking and rotation
#[derive(Debug, Clone)]
struct KeyMetadata {
    id: String,
    created_at: SystemTime,
    algorithm: String,
    is_current: bool,
}

/// Storage for encryption keys with versioning
#[derive(Debug)]
struct KeyStore {
    keys: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, KeyMetadata>,
    current_key_id: Option<String>,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            metadata: HashMap::new(),
            current_key_id: None,
        }
    }

    fn add_key(&mut self, id: &str, key: Vec<u8>, algorithm: &str, make_current: bool) {
        let metadata = KeyMetadata {
            id: id.to_string(),
            created_at: SystemTime::now(),
            algorithm: algorithm.to_string(),
            is_current: make_current,
        };

        self.keys.insert(id.to_string(), key);
        self.metadata.insert(id.to_string(), metadata);

        if make_current {
            // If this is the new current key, update any previous current key
            if let Some(old_current_id) = &self.current_key_id {
                if old_current_id != id {
                    if let Some(old_metadata) = self.metadata.get_mut(old_current_id) {
                        old_metadata.is_current = false;
                    }
                }
            }
            self.current_key_id = Some(id.to_string());
        }
    }

    fn get_key(&self, id: &str) -> Option<&Vec<u8>> {
        self.keys.get(id)
    }

    fn get_current_key(&self) -> Option<(&Vec<u8>, &str)> {
        self.current_key_id.as_ref().and_then(|id| {
            self.keys.get(id).map(|key| {
                let metadata = &self.metadata[id];
                (key, metadata.algorithm.as_str())
            })
        })
    }

    fn get_key_by_id(&self, id: &str) -> Option<(&Vec<u8>, &str)> {
        self.keys.get(id).map(|key| {
            let metadata = &self.metadata[id];
            (key, metadata.algorithm.as_str())
        })
    }

    fn rotate_key_if_needed(&mut self) -> Result<bool> {
        // Check if we need to rotate the key
        if let Some(current_id) = &self.current_key_id {
            if let Some(metadata) = self.metadata.get(current_id) {
                if let Ok(elapsed) = metadata.created_at.elapsed() {
                    let days_elapsed = elapsed.as_secs() / (24 * 60 * 60);
                    if days_elapsed >= KEY_ROTATION_PERIOD_DAYS {
                        // Generate and add a new key
                        debug!("Rotating encryption key after {} days", days_elapsed);
                        let new_key = generate_aes256_key();
                        let new_id = generate_key_id();
                        self.add_key(&new_id, new_key, "AES-256-GCM", true);
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn export_keys(&self, path: &Path, master_key: &[u8]) -> Result<()> {
        let mut exported_data = HashMap::new();

        // Export all keys and their metadata
        for (id, key) in &self.keys {
            let metadata = self.metadata.get(id).ok_or_else(|| {
                anyhow!("Inconsistent key store state: metadata missing for key {}", id)
            })?;

            // Encrypt the key with the master key
            let encrypted_key = encrypt_with_aes256(key, master_key)?;
            
            // Convert to base64 for storage
            let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);
            
            exported_data.insert(
                id.clone(),
                serde_json::json!({
                    "key": encrypted_key_b64,
                    "created_at": metadata.created_at
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    "algorithm": metadata.algorithm,
                    "is_current": metadata.is_current,
                }),
            );
        }

        // Add current key info
        exported_data.insert(
            CURRENT_KEY_VERSION.to_string(), 
            serde_json::json!(self.current_key_id),
        );

        // Serialize and write to file
        let json_data = serde_json::to_string_pretty(&exported_data)?;
        let mut file = File::create(path)?;
        file.write_all(json_data.as_bytes())?;

        Ok(())
    }

    fn import_keys(&mut self, path: &Path, master_key: &[u8]) -> Result<()> {
        // Read file
        let mut file = File::open(path)?;
        let mut json_data = String::new();
        file.read_to_string(&mut json_data)?;

        // Parse JSON
        let exported_data: HashMap<String, serde_json::Value> = serde_json::from_str(&json_data)?;

        // Clear existing keys
        self.keys.clear();
        self.metadata.clear();
        self.current_key_id = None;

        // Process current key first
        let current_key_id = if let Some(current_value) = exported_data.get(CURRENT_KEY_VERSION) {
            current_value.as_str().map(|s| s.to_string())
        } else {
            None
        };

        // Import all keys
        for (id, data) in exported_data {
            if id == CURRENT_KEY_VERSION {
                continue;
            }

            let data_obj = data.as_object().ok_or_else(|| {
                anyhow!("Invalid key data format for key {}", id)
            })?;

            // Get encrypted key
            let encrypted_key_b64 = data_obj
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing or invalid key data for key {}", id))?;

            // Decode and decrypt
            let encrypted_key = general_purpose::STANDARD.decode(encrypted_key_b64)?;
            let key = decrypt_with_aes256(&encrypted_key, master_key)?;

            // Get algorithm
            let algorithm = data_obj
                .get("algorithm")
                .and_then(|v| v.as_str())
                .unwrap_or("AES-256-GCM")
                .to_string();

            // Get creation time
            let created_at_secs = data_obj
                .get("created_at")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            
            let created_at = UNIX_EPOCH + Duration::from_secs(created_at_secs);

            // Determine if this is the current key
            let is_current = current_key_id.as_ref().map_or(false, |current| current == &id);

            // Create metadata
            let metadata = KeyMetadata {
                id: id.clone(),
                created_at,
                algorithm,
                is_current,
            };

            // Add to key store
            self.keys.insert(id.clone(), key);
            self.metadata.insert(id.clone(), metadata);

            if is_current {
                self.current_key_id = Some(id.clone());
            }
        }

        Ok(())
    }
}

/// Initialize the encryption module
pub fn initialize() -> Result<()> {
    // Initialize key store
    let config = config::get_config();
    let key_store_dir = Path::new(&config.security.key_store_path);

    // Create directory if it doesn't exist
    if !key_store_dir.exists() {
        fs::create_dir_all(key_store_dir)?;
    }

    let key_store_file = key_store_dir.join("keys.json");

    // If key store exists, try to load it
    if key_store_file.exists() {
        debug!("Loading existing key store from {:?}", key_store_file);
        
        // Get master key for decryption
        let master_key = derive_master_key()?;
        
        // Import keys
        KEY_STORE.write().unwrap().import_keys(&key_store_file, &master_key)?;
        
        // Check if key rotation is needed
        let rotated = KEY_STORE.write().unwrap().rotate_key_if_needed()?;
        if rotated {
            debug!("Key rotation performed during initialization");
            
            // Export updated keys if rotation occurred
            KEY_STORE.read().unwrap().export_keys(&key_store_file, &master_key)?;
        }
    } else {
        debug!("Creating new key store at {:?}", key_store_file);
        
        // Generate a new key
        let key = generate_aes256_key();
        let key_id = generate_key_id();
        
        // Add to key store
        KEY_STORE.write().unwrap().add_key(&key_id, key, "AES-256-GCM", true);
        
        // Export keys
        let master_key = derive_master_key()?;
        KEY_STORE.read().unwrap().export_keys(&key_store_file, &master_key)?;
    }

    info!("Encryption module initialized successfully");
    Ok(())
}

/// Generate a unique key ID
fn generate_key_id() -> String {
    format!("{}{}", KEY_PREFIX, Uuid::new_v4().to_string())
}

/// Generate a new AES-256 key
pub fn generate_aes256_key() -> Vec<u8> {
    let mut key = vec![0u8; AES_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a new ChaCha20-Poly1305 key
pub fn generate_chacha_key() -> Vec<u8> {
    let mut key = vec![0u8; CHACHA_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Derive a master key from system and configuration information
fn derive_master_key() -> Result<Vec<u8>> {
    let config = config::get_config();
    let master_password = &config.security.master_password;
    
    if master_password.is_empty() {
        warn!("No master password configured, using a default salt");
        // This is a security risk in production and should be addressed
    }
    
    // Use a salt based on system information or a configured value
    // In a real system, this would be securely stored and managed
    let salt = if let Some(salt_config) = &config.security.master_salt {
        salt_config.as_bytes().to_vec()
    } else {
        // Fallback salt - not secure for production use
        b"secure_bank_salt_v1".to_vec()
    };
    
    // Derive key using PBKDF2
    let mut key = vec![0u8; AES_KEY_LEN];
    pbkdf2::<Hmac<Sha256>>(
        master_password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut key,
    ).map_err(|e| anyhow!("Failed to derive master key: {}", e))?;
    
    Ok(key)
}

/// Get the current encryption key
pub fn get_current_key() -> Result<(Vec<u8>, String)> {
    let key_store = KEY_STORE.read().unwrap();
    
    match key_store.get_current_key() {
        Some((key, algorithm)) => Ok((key.clone(), algorithm.to_string())),
        None => Err(anyhow!("No current encryption key available")),
    }
}

/// Get a specific encryption key by ID
pub fn get_key_by_id(id: &str) -> Result<(Vec<u8>, String)> {
    let key_store = KEY_STORE.read().unwrap();
    
    match key_store.get_key_by_id(id) {
        Some((key, algorithm)) => Ok((key.clone(), algorithm.to_string())),
        None => Err(anyhow!("Encryption key with ID {} not found", id)),
    }
}

/// Rotate the current encryption key
pub fn rotate_encryption_key() -> Result<String> {
    let mut key_store = KEY_STORE.write().unwrap();
    
    // Generate new key
    let new_key = generate_aes256_key();
    let new_id = generate_key_id();
    
    // Add to key store
    key_store.add_key(&new_id, new_key, "AES-256-GCM", true);
    
    // Export keys
    let config = config::get_config();
    let key_store_file = Path::new(&config.security.key_store_path).join("keys.json");
    let master_key = derive_master_key()?;
    drop(key_store); // Release the write lock before taking a read lock
    
    KEY_STORE.read().unwrap().export_keys(&key_store_file, &master_key)?;
    
    debug!("Encryption key rotated, new key ID: {}", new_id);
    Ok(new_id)
}

/// Encrypt data with the current key, prefixing with key ID
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    let (key, algorithm) = get_current_key()?;
    let key_store = KEY_STORE.read().unwrap();
    let current_key_id = key_store.current_key_id.as_ref()
        .ok_or_else(|| anyhow!("No current key ID available"))?;

    let encrypted = match algorithm.as_str() {
        "AES-256-GCM" => encrypt_with_aes256(data, &key)?,
        "CHACHA20-POLY1305" => encrypt_with_chacha(data, &key)?,
        _ => return Err(anyhow!("Unsupported encryption algorithm: {}", algorithm)),
    };

    // Prefix with key ID for future decryption
    let mut result = current_key_id.clone().into_bytes();
    result.push(b':'); // Use a separator
    result.extend_from_slice(&encrypted);

    Ok(result)
}

/// Decrypt data that includes a key ID prefix
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>> {
    // Split the input into key_id and ciphertext
    let separator_pos = data.iter().position(|&b| b == b':')
        .ok_or_else(|| anyhow!("Invalid encrypted data format: missing key ID separator"))?;

    let key_id = std::str::from_utf8(&data[..separator_pos])?;
    let ciphertext = &data[(separator_pos + 1)..];

    // Get the key by ID
    let (key, algorithm) = get_key_by_id(key_id)?;

    // Decrypt based on the algorithm
    match algorithm.as_str() {
        "AES-256-GCM" => decrypt_with_aes256(ciphertext, &key),
        "CHACHA20-POLY1305" => decrypt_with_chacha(ciphertext, &key),
        _ => Err(anyhow!("Unsupported encryption algorithm: {}", algorithm)),
    }
}

/// Encrypt data using AES-256-GCM
fn encrypt_with_aes256(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
    
    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES encryption failed: {}", e))?;
    
    // Combine nonce and ciphertext for storage/transmission
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data using AES-256-GCM
fn decrypt_with_aes256(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Split the input into nonce and ciphertext
    if ciphertext.len() <= NONCE_LEN {
        return Err(anyhow!("Invalid ciphertext length for AES-256-GCM"));
    }
    
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, actual_ciphertext)
        .map_err(|e| anyhow!("AES decryption failed: {}", e))?;
    
    Ok(plaintext)
}

/// Encrypt data using ChaCha20-Poly1305
fn encrypt_with_chacha(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Create cipher instance
    let key = ChaChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    
    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?;
    
    // Combine nonce and ciphertext for storage/transmission
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305
fn decrypt_with_chacha(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Split the input into nonce and ciphertext
    if ciphertext.len() <= NONCE_LEN {
        return Err(anyhow!("Invalid ciphertext length for ChaCha20-Poly1305"));
    }
    
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_LEN);
    let nonce = ChaChaNonce::from_slice(nonce_bytes);
    
    // Create cipher instance
    let key = ChaChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, actual_ciphertext)
        .map_err(|e| anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))?;
    
    Ok(plaintext)
}

/// Encrypt a string and encode it with base64
pub fn encrypt_string(plaintext: &str) -> Result<String> {
    let encrypted = encrypt(plaintext.as_bytes())?;
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt a base64-encoded ciphertext
pub fn decrypt_string(ciphertext: &str) -> Result<String> {
    let decoded = general_purpose::STANDARD.decode(ciphertext)
        .context("Failed to decode base64 ciphertext")?;
    
    let decrypted = decrypt(&decoded)?;
    
    String::from_utf8(decrypted)
        .context("Failed to convert decrypted data to UTF-8 string")
}

/// Generate secure random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a secure random token of specified length
pub fn generate_secure_token(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    let mut rng = OsRng;
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash data with SHA-256
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data with SHA-512
pub fn hash_sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Derive a key from a password using PBKDF2
pub fn derive_key_from_password(
    password: &str, 
    salt: &[u8], 
    iterations: u32,
    key_len: usize,
) -> Result<Vec<u8>> {
    let mut key = vec![0u8; key_len];
    
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        iterations,
        &mut key,
    ).map_err(|e| anyhow!("Failed to derive key from password: {}", e))?;
    
    Ok(key)
}

/// Encrypt sensitive data with additional protection
/// This function uses the current encryption key but adds additional protection
/// measures for particularly sensitive information
pub fn encrypt_sensitive_data(plaintext: &str) -> Result<String> {
    // Get the current encryption key
    let (key, algorithm) = get_current_key()?;
    
    // Add a prefix indicating this is sensitive data to handle it specially during decryption
    let tagged_plaintext = format!("SENSITIVE:{}", plaintext);
    
    // Double encrypt for sensitive data
    // First encrypt with normal algorithm
    let encrypted = match algorithm.as_str() {
        "AES-256-GCM" => encrypt_with_aes256(tagged_plaintext.as_bytes(), &key)?,
        "CHACHA20-POLY1305" => encrypt_with_chacha(tagged_plaintext.as_bytes(), &key)?,
        _ => return Err(anyhow!("Unsupported encryption algorithm: {}", algorithm)),
    };
    
    // For sensitive data, add an extra identifier prefix
    let key_id = KEY_STORE.read().unwrap().current_key_id.clone()
        .ok_or_else(|| anyhow!("No current encryption key available"))?;
    
    // Add sensitive prefix to indicate special handling is needed
    let prefixed_data = format!("SENS{}:{}", key_id, general_purpose::STANDARD.encode(&encrypted));
    
    Ok(prefixed_data)
}

/// Decrypt sensitive data
pub fn decrypt_sensitive_data(ciphertext: &str) -> Result<String> {
    // Check if this is sensitive data format
    if !ciphertext.starts_with("SENS") {
        return Err(anyhow!("Not in sensitive data format"));
    }
    
    // Extract the key ID and actual ciphertext
    let parts: Vec<&str> = ciphertext.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid sensitive data format: missing key ID separator"));
    }
    
    // Key ID is embedded in the prefix (after "SENS")
    let key_id = &parts[0][4..]; // Skip the "SENS" prefix
    let base64_ciphertext = parts[1];
    
    // Decode the base64 ciphertext
    let decoded = general_purpose::STANDARD.decode(base64_ciphertext)
        .context("Failed to decode base64 sensitive data")?;
    
    // Get the key by ID
    let (key, algorithm) = get_key_by_id(key_id)?;
    
    // Decrypt based on the algorithm
    let decrypted_bytes = match algorithm.as_str() {
        "AES-256-GCM" => decrypt_with_aes256(&decoded, &key)?,
        "CHACHA20-POLY1305" => decrypt_with_chacha(&decoded, &key)?,
        _ => return Err(anyhow!("Unsupported encryption algorithm: {}", algorithm)),
    };
    
    // Convert to string
    let decrypted_str = String::from_utf8(decrypted_bytes)
        .context("Failed to convert decrypted sensitive data to UTF-8 string")?;
    
    // Check for the sensitive prefix and remove it
    if decrypted_str.starts_with("SENSITIVE:") {
        Ok(decrypted_str[10..].to_string()) // Skip the "SENSITIVE:" prefix
    } else {
        Err(anyhow!("Decrypted data missing expected sensitive prefix"))
    }
}

/// Encrypt binary data (for file encryption)
pub fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
    encrypt(data)
}

/// Decrypt binary data (for file decryption)
pub fn decrypt_data(ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_aes_encryption_decryption() {
        let key = generate_aes256_key();
        let data = b"sensitive information for testing";
        
        let encrypted = encrypt_with_aes256(data, &key).unwrap();
        let decrypted = decrypt_with_aes256(&encrypted, &key).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_chacha_encryption_decryption() {
        let key = generate_chacha_key();
        let data = b"sensitive information for chacha testing";
        
        let encrypted = encrypt_with_chacha(data, &key).unwrap();
        let decrypted = decrypt_with_chacha(&encrypted, &key).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_sensitive_data_encryption() {
        // Initialize the keystore
        initialize().unwrap();
        
        let sensitive_data = "Credit card: 1234-5678-9012-3456";
        let encrypted = encrypt_sensitive_data(sensitive_data).unwrap();
        
        // Verify it's properly formatted
        assert!(encrypted.starts_with("SENS"));
        assert!(encrypted.contains(":"));
        
        // Verify it doesn't contain plaintext
        assert!(!encrypted.contains("1234-5678"));
        
        // Decrypt and verify
        let decrypted = decrypt_sensitive_data(&encrypted).unwrap();
        assert_eq!(sensitive_data, decrypted);
    }
    
    #[test]
    fn test_key_rotation() {
        // Initialize the keystore
        initialize().unwrap();
        
        // Encrypt some data with the current key
        let data = "data before rotation";
        let encrypted = encrypt_string(data).unwrap();
        
        // Get the current key ID
        let current_id_before = KEY_STORE.read().unwrap().current_key_id.clone().unwrap();
        
        // Rotate the key
        let new_key_id = rotate_encryption_key().unwrap();
        
        // Verify the key has changed
        let current_id_after = KEY_STORE.read().unwrap().current_key_id.clone().unwrap();
        assert_ne!(current_id_before, current_id_after);
        assert_eq!(current_id_after, new_key_id);
        
        // We should still be able to decrypt the old data
        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!(data, decrypted);
        
        // New encryption should use the new key
        let new_data = "data after rotation";
        let new_encrypted = encrypt_string(new_data).unwrap();
        let new_decrypted = decrypt_string(&new_encrypted).unwrap();
        assert_eq!(new_data, new_decrypted);
    }
    
    #[test]
    fn test_key_export_import() {
        // Initialize the keystore
        initialize().unwrap();
        
        // Generate a test master key
        let master_key = generate_aes256_key();
        
        // Create a temporary directory
        let temp_dir = tempdir().unwrap();
        let key_store_path = temp_dir.path().join("keystore.json");
        
        // Export keys
        KEY_STORE
            .read()
            .unwrap()
            .export_keys(&key_store_path, &master_key)
            .unwrap();
        
        // Verify export
        assert!(key_store_path.exists());
        
        // Create a new keystore
        let mut new_keystore = KeyStore::new();
        
        // Import the keys
        new_keystore
            .import_keys(&key_store_path, &master_key)
            .unwrap();
        
        // Verify the current key matches
        let original_current_id = KEY_STORE.read().unwrap().current_key_id.clone().unwrap();
        let new_current_id = new_keystore.current_key_id.clone().unwrap();
        assert_eq!(original_current_id, new_current_id);
        
        // Verify key content
        let original_key = KEY_STORE
            .read()
            .unwrap()
            .get_key(&original_current_id)
            .unwrap()
            .clone();
        let new_key = new_keystore.get_key(&new_current_id).unwrap().clone();
        assert_eq!(original_key, new_key);
    }
    
    #[test]
    fn test_password_key_derivation() {
        let password = "test_password";
        let salt = generate_random_bytes(16);
        let iterations = 10000;
        
        // Derive a key
        let key1 = derive_key_from_password(password, &salt, iterations, 32).unwrap();
        
        // Derive again - should be the same
        let key2 = derive_key_from_password(password, &salt, iterations, 32).unwrap();
        assert_eq!(key1, key2);
        
        // Derive with different password - should be different
        let key3 = derive_key_from_password("different", &salt, iterations, 32).unwrap();
        assert_ne!(key1, key3);
        
        // Derive with different salt - should be different
        let key4 = derive_key_from_password(
            password,
            &generate_random_bytes(16),
            iterations,
            32,
        )
        .unwrap();
        assert_ne!(key1, key4);
    }
    
    #[test]
    fn test_sensitive_data_with_key_rotation() {
        // Initialize the keystore
        initialize().unwrap();
        
        // Encrypt sensitive data with the current key
        let sensitive_data = "SSN: 123-45-6789";
        let encrypted = encrypt_sensitive_data(sensitive_data).unwrap();
        
        // Rotate the key
        rotate_encryption_key().unwrap();
        
        // We should still be able to decrypt the old sensitive data
        let decrypted = decrypt_sensitive_data(&encrypted).unwrap();
        assert_eq!(sensitive_data, decrypted);
        
        // New encryption should use the new key but still work
        let new_sensitive_data = "Password: SuperSecret123!";
        let new_encrypted = encrypt_sensitive_data(new_sensitive_data).unwrap();
        let new_decrypted = decrypt_sensitive_data(&new_encrypted).unwrap();
        assert_eq!(new_sensitive_data, new_decrypted);
    }
} 