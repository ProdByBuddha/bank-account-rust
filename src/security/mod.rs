use anyhow::{Result, Context, anyhow};
use log::{debug, warn};
use rand::{RngCore, rngs::OsRng};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Version, Params,
};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{engine::general_purpose, Engine as _};

pub mod jwt;
pub mod totp;
pub mod compliance;

// Length of the salt for password hashing
const SALT_LEN: usize = 16;
// Length of the AES-256 key
const AES_KEY_LEN: usize = 32;
// Length of the nonce for AES-GCM
const NONCE_LEN: usize = 12;

/// Generate a random salt for password hashing
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Hash a password using Argon2id
pub fn hash_password(password: &str, iterations: u32) -> Result<(String, String)> {
    // Generate a random salt
    let salt = SaltString::generate(&mut ArgonOsRng);
    
    // Configure Argon2id
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            iterations, // Memory cost (kibibytes)
            1,         // Iterations
            1,         // Parallelism
            None,      // Output length (defaults to 32 bytes)
        ).expect("Invalid Argon2 parameters"),
    );
    
    // Hash the password
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .context("Failed to hash password")?
        .to_string();
    
    Ok((password_hash, salt.as_str().to_string()))
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    // Parse the hash
    let parsed_hash = PasswordHash::new(hash)
        .context("Failed to parse password hash")?;
    
    // Verify the password
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);
    
    // Return the result (success = true, error = false)
    match result {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a random AES-256 key
pub fn generate_encryption_key() -> [u8; AES_KEY_LEN] {
    let mut key = [0u8; AES_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt data with AES-256-GCM
pub fn encrypt(plaintext: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .context("Failed to create AES cipher")?;
    
    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .context("Encryption failed")?;
    
    // Combine nonce and ciphertext for storage/transmission
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(ciphertext: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    // Split the input into nonce and ciphertext
    if ciphertext.len() <= NONCE_LEN {
        return Err(anyhow!("Invalid ciphertext length"));
    }
    
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .context("Failed to create AES cipher")?;
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, actual_ciphertext)
        .context("Decryption failed")?;
    
    Ok(plaintext)
}

/// Encrypt a string with AES-256-GCM and encode with base64
pub fn encrypt_string(plaintext: &str, key: &[u8; AES_KEY_LEN]) -> Result<String> {
    let encrypted = encrypt(plaintext.as_bytes(), key)?;
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt a base64-encoded AES-256-GCM ciphertext
pub fn decrypt_string(ciphertext: &str, key: &[u8; AES_KEY_LEN]) -> Result<String> {
    let decoded = general_purpose::STANDARD.decode(ciphertext)
        .context("Failed to decode base64 ciphertext")?;
    
    let decrypted = decrypt(&decoded, key)?;
    
    String::from_utf8(decrypted)
        .context("Failed to convert decrypted data to UTF-8 string")
}

/// Calculate HMAC-SHA256 for data integrity verification
pub fn calculate_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Create HMAC instance
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .context("Failed to create HMAC")?;
    
    // Update with input data
    mac.update(data);
    
    // Finalize and return the HMAC
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA256 for data integrity
pub fn verify_hmac(data: &[u8], key: &[u8], expected_hmac: &[u8]) -> Result<bool> {
    // Create HMAC instance
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .context("Failed to create HMAC")?;
    
    // Update with input data
    mac.update(data);
    
    // Verify the HMAC
    match mac.verify_slice(expected_hmac) {
        Ok(_) => Ok(true),
        Err(_) => {
            warn!("HMAC verification failed - data integrity compromised");
            Ok(false)
        }
    }
}

/// Derive an encryption key from a password using PBKDF2
pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; AES_KEY_LEN]> {
    use pbkdf2::pbkdf2;
    
    let mut key = [0u8; AES_KEY_LEN];
    
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        iterations,
        &mut key,
    ).context("Failed to derive key from password")?;
    
    Ok(key)
}

/// Generate a secure random token
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hash_and_verify() {
        let password = "P@ssw0rd123!";
        let (hash, _salt) = hash_password(password, 10000).unwrap();
        
        // Verify correct password
        let result = verify_password(password, &hash).unwrap();
        assert!(result);
        
        // Verify incorrect password
        let result = verify_password("wrong_password", &hash).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_encryption_key();
        let plaintext = b"This is a secret message";
        
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_encrypt_decrypt_string() {
        let key = generate_encryption_key();
        let plaintext = "This is a secret message";
        
        let encrypted = encrypt_string(plaintext, &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_hmac() {
        let key = generate_encryption_key();
        let data = b"Data to protect with HMAC";
        
        let hmac = calculate_hmac(data, &key).unwrap();
        
        // Verify correct data
        let result = verify_hmac(data, &key, &hmac).unwrap();
        assert!(result);
        
        // Verify tampered data
        let tampered_data = b"Tampered data to protect with HMAC";
        let result = verify_hmac(tampered_data, &key, &hmac).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "P@ssw0rd123!";
        let salt = generate_salt();
        let iterations = 10000;
        
        let key1 = derive_key_from_password(password, &salt, iterations).unwrap();
        let key2 = derive_key_from_password(password, &salt, iterations).unwrap();
        
        // Same password and salt should produce the same key
        assert_eq!(key1, key2);
        
        // Different password should produce a different key
        let key3 = derive_key_from_password("different_password", &salt, iterations).unwrap();
        assert_ne!(key1, key3);
        
        // Different salt should produce a different key
        let different_salt = generate_salt();
        let key4 = derive_key_from_password(password, &different_salt, iterations).unwrap();
        assert_ne!(key1, key4);
    }
} 