use anyhow::{Result, Context, anyhow};
use log::{debug, warn};
use rand::{RngCore, rngs::OsRng};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

pub mod jwt;
pub mod totp;
pub mod compliance;
pub mod password;
pub mod encryption;  // New encryption module with enhanced key management
pub mod auth;  // New authentication middleware module
pub mod trusted_devices;  // New module for trusted device management

// Re-export key functions from encryption module
pub use encryption::{
    encrypt_string as encrypt_with_current_key,
    decrypt_string as decrypt_with_current_key,
    generate_secure_token,
    derive_key_from_password as derive_key,
    hash_sha256,
    hash_sha512,
    generate_random_bytes,
};

// Re-export key authentication functions
pub use auth::{
    authenticate,
    require_role,
    require_tfa,
    check_session_timeout,
    refresh_if_needed,
    logout,
    logout_all_devices,
    AuthResult,
    AuthError,
    SessionTimeoutConfig,
};

// Re-export TOTP functions
pub use totp::{
    generate_secret as generate_totp_secret,
    create_totp,
    generate_code as generate_totp_code,
    verify_code as verify_totp_code,
    generate_uri as generate_totp_uri,
    generate_recovery_codes,
    hash_recovery_code,
    TotpConfig,
};

// Length of the AES-256 key
const AES_KEY_LEN: usize = 32;
// Length of the nonce for AES-GCM
const NONCE_LEN: usize = 12;

/// Initialize security components
pub fn initialize() -> Result<()> {
    // Initialize password pepper
    password::initialize_password_pepper()?;
    
    // Initialize encryption key store
    encryption::initialize()?;
    
    debug!("Security components initialized");
    Ok(())
}

/// Generate a random AES-256 key (legacy method, prefer using encryption module)
pub fn generate_encryption_key() -> [u8; AES_KEY_LEN] {
    let mut key = [0u8; AES_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt data with AES-256-GCM (legacy method, prefer using encryption module)
pub fn encrypt(plaintext: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
    
    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    // Combine nonce and ciphertext for storage/transmission
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with AES-256-GCM (legacy method, prefer using encryption module)
pub fn decrypt(ciphertext: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    // Split the input into nonce and ciphertext
    if ciphertext.len() <= NONCE_LEN {
        return Err(anyhow!("Invalid ciphertext length"));
    }
    
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, actual_ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;
    
    Ok(plaintext)
}

/// Encrypt a string with AES-256-GCM and encode with base64 (legacy method, prefer using encryption module)
pub fn encrypt_string(plaintext: &str, key: &[u8; AES_KEY_LEN]) -> Result<String> {
    let encrypted = encrypt(plaintext.as_bytes(), key)?;
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt a base64-encoded AES-256-GCM ciphertext (legacy method, prefer using encryption module)
pub fn decrypt_string(ciphertext: &str, key: &[u8; AES_KEY_LEN]) -> Result<String> {
    let decoded = general_purpose::STANDARD.decode(ciphertext)
        .context("Failed to decode base64 ciphertext")?;
    
    let decrypted = decrypt(&decoded, key)?;
    
    String::from_utf8(decrypted)
        .context("Failed to convert decrypted data to UTF-8 string")
}

/// Derive an encryption key from a password using PBKDF2 (legacy method, prefer using encryption module)
pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; AES_KEY_LEN]> {
    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha2::Sha256;
    
    let mut key = [0u8; AES_KEY_LEN];
    
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        iterations,
        &mut key,
    ).map_err(|e| anyhow!("Failed to derive key from password: {}", e))?;
    
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_encryption_key();
        let data = b"sensitive information";
        
        let encrypted = encrypt(data, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_encrypt_decrypt_string() {
        let key = generate_encryption_key();
        let data = "sensitive string information";
        
        let encrypted = encrypt_string(data, &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "secure_password";
        let salt = b"random_salt_123";
        let iterations = 10000;
        
        let key1 = derive_key_from_password(password, salt, iterations).unwrap();
        let key2 = derive_key_from_password(password, salt, iterations).unwrap();
        
        // Same password, salt, and iterations should produce the same key
        assert_eq!(key1, key2);
        
        // Different password should produce different key
        let key3 = derive_key_from_password("different_password", salt, iterations).unwrap();
        assert_ne!(key1, key3);
        
        // Different salt should produce different key
        let key4 = derive_key_from_password(password, b"different_salt", iterations).unwrap();
        assert_ne!(key1, key4);
    }
} 