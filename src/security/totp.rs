use anyhow::{Context, Result};
use log::debug;
use totp_rs::{Algorithm, TOTP, Secret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// TOTP Configuration
const DIGITS: usize = 6;
const PERIOD: u64 = 30;
const ALGORITHM: Algorithm = Algorithm::SHA1;
const ISSUER: &str = "Secure Banking CLI";
const SECRET_LEN: usize = 32;

/// TOTP configuration for easier serialization/deserialization
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TotpConfig {
    pub secret: String,
    pub algorithm: String,
    pub digits: usize,
    pub period: u64,
}

/// Generate a new TOTP secret
pub fn generate_secret() -> String {
    let mut rng = rand::thread_rng();
    let mut secret = vec![0u8; SECRET_LEN];
    rng.fill_bytes(&mut secret);
    
    base32::encode(base32::Alphabet::RFC4648 { padding: true }, &secret)
}

/// Create a new TOTP instance with the given secret
pub fn create_totp(secret: &str, username: &str) -> Result<TOTP> {
    let secret = Secret::Encoded(secret.to_string());
    
    let totp = TOTP::new(
        ALGORITHM,
        DIGITS,
        1,
        PERIOD,
        secret,
        Some(ISSUER.to_string()),
        username.to_string(),
    ).context("Failed to create TOTP instance")?;
    
    Ok(totp)
}

/// Generate a TOTP code for the current time
pub fn generate_code(totp: &TOTP) -> String {
    totp.generate_current().to_string()
}

/// Verify a TOTP code
pub fn verify_code(totp: &TOTP, code: &str) -> bool {
    totp.check_current(code)
}

/// Get the current UNIX timestamp
pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Generate a TOTP URI for QR code generation
pub fn generate_uri(totp: &TOTP) -> String {
    totp.get_url()
}

/// Generate a set of recovery codes
pub fn generate_recovery_codes(count: usize, length: usize) -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    (0..count)
        .map(|_| {
            let code: String = (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            
            // Format with hyphens for better readability (e.g., XXXX-XXXX-XXXX-XXXX)
            code.chars()
                .enumerate()
                .fold(String::new(), |mut acc, (i, c)| {
                    if i > 0 && i % 4 == 0 {
                        acc.push('-');
                    }
                    acc.push(c);
                    acc
                })
        })
        .collect()
}

/// Hash a recovery code for secure storage
pub fn hash_recovery_code(code: &str) -> Result<String> {
    use sha2::{Sha256, Digest};
    
    // Remove hyphens for hashing
    let clean_code = code.replace("-", "");
    
    // Hash with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(clean_code.as_bytes());
    let hash = hasher.finalize();
    
    // Return hex string
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_totp_generation_and_verification() {
        let username = "testuser";
        let secret = generate_secret();
        
        let totp = create_totp(&secret, username).unwrap();
        let code = generate_code(&totp);
        
        // Verify the code
        assert!(verify_code(&totp, &code));
        
        // Verify an invalid code
        assert!(!verify_code(&totp, "000000"));
    }
    
    #[test]
    fn test_recovery_codes() {
        // Generate recovery codes
        let codes = generate_recovery_codes(5, 16);
        assert_eq!(codes.len(), 5);
        
        // Check format (should have hyphens every 4 characters)
        for code in &codes {
            assert!(code.contains('-'));
            assert_eq!(code.len(), 19); // 16 digits + 3 hyphens
        }
        
        // Test hashing
        let hash = hash_recovery_code(&codes[0]).unwrap();
        assert!(!hash.is_empty());
    }
    
    #[test]
    fn test_totp_uri() {
        let username = "testuser";
        let secret = generate_secret();
        
        let totp = create_totp(&secret, username).unwrap();
        let uri = generate_uri(&totp);
        
        // URI should contain the issuer and username
        assert!(uri.contains(ISSUER));
        assert!(uri.contains(username));
        assert!(uri.starts_with("otpauth://"));
    }
}