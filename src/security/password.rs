use anyhow::{Result, Context};
use argon2::{
    password_hash::{SaltString, PasswordHasher, PasswordVerifier, PasswordHash},
    Argon2, Algorithm, Version, Params
};
use rand::{rngs::OsRng, RngCore};
use log::{debug, warn};
use std::sync::RwLock;
use lazy_static::lazy_static;

// Pepper for password hashing - a secret value not stored in the database
// In a real system, this would be stored in a secure configuration and not hardcoded
lazy_static! {
    static ref PASSWORD_PEPPER: RwLock<Option<[u8; 32]>> = RwLock::new(None);
}

/// Initialize the password pepper
pub fn initialize_password_pepper() -> Result<()> {
    debug!("Initializing password pepper");
    
    // In a production system, this would be loaded from a secure configuration or environment
    // For this implementation, we'll generate a random pepper if not already set
    if PASSWORD_PEPPER.read().unwrap().is_none() {
        let mut pepper = [0u8; 32];
        OsRng.fill_bytes(&mut pepper);
        *PASSWORD_PEPPER.write().unwrap() = Some(pepper);
        debug!("Password pepper generated");
    } else {
        debug!("Password pepper already initialized");
    }
    
    Ok(())
}

/// Get the password pepper
fn get_password_pepper() -> Result<[u8; 32]> {
    match *PASSWORD_PEPPER.read().unwrap() {
        Some(pepper) => Ok(pepper),
        None => {
            // If not initialized, initialize it now
            initialize_password_pepper()?;
            match *PASSWORD_PEPPER.read().unwrap() {
                Some(pepper) => Ok(pepper),
                None => {
                    warn!("Failed to initialize password pepper");
                    Err(anyhow::anyhow!("Password pepper not initialized"))
                }
            }
        }
    }
}

/// Generate a random salt for password hashing
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

/// Hash a password using Argon2id with salt and pepper
pub fn hash_password(password: &str, iterations: u32) -> Result<(String, String)> {
    // Get the pepper
    let pepper = get_password_pepper()?;
    
    // Generate a random salt
    let salt = generate_salt();
    
    // Combine password with pepper
    let peppered_password = apply_pepper(password, &pepper)?;
    
    // Configure Argon2id
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            iterations, // Memory cost (kibibytes)
            2,         // Iterations
            1,         // Parallelism
            None,      // Output length (defaults to 32 bytes)
        ).map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?,
    );
    
    // Hash the password
    let password_hash = argon2.hash_password(peppered_password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
        .to_string();
    
    Ok((password_hash, salt.as_str().to_string()))
}

/// Verify a password against a hash using the pepper
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    // Get the pepper
    let pepper = get_password_pepper()?;
    
    // Combine password with pepper
    let peppered_password = apply_pepper(password, &pepper)?;
    
    // Parse the hash
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;
    
    // Verify the password
    let result = Argon2::default().verify_password(peppered_password.as_bytes(), &parsed_hash);
    
    // Return the result (success = true, error = false)
    match result {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Apply the pepper to a password
fn apply_pepper(password: &str, pepper: &[u8; 32]) -> Result<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    // Create HMAC with the pepper as key
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
        .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
    
    // Update with password
    mac.update(password.as_bytes());
    
    // Finalize and get result
    let result = mac.finalize().into_bytes();
    
    // Convert to hex string for easier handling
    Ok(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing_with_pepper() {
        // Initialize pepper
        initialize_password_pepper().unwrap();
        
        // Test password
        let password = "securePassword123!";
        
        // Hash the password
        let (hash, salt) = hash_password(password, 4096).unwrap();
        
        // Verify correct password
        let result = verify_password(password, &hash).unwrap();
        assert!(result, "Password verification should succeed with correct password");
        
        // Verify incorrect password
        let result = verify_password("wrongPassword", &hash).unwrap();
        assert!(!result, "Password verification should fail with incorrect password");
    }
    
    #[test]
    fn test_pepper_consistency() {
        // Initialize pepper
        initialize_password_pepper().unwrap();
        
        // Get the pepper twice - should be the same value
        let pepper1 = get_password_pepper().unwrap();
        let pepper2 = get_password_pepper().unwrap();
        
        assert_eq!(pepper1, pepper2, "Pepper should be consistent between calls");
        
        // Apply pepper to the same password twice - should get the same result
        let password = "testPassword";
        let peppered1 = apply_pepper(password, &pepper1).unwrap();
        let peppered2 = apply_pepper(password, &pepper1).unwrap();
        
        assert_eq!(peppered1, peppered2, "Peppered password should be consistent");
    }
} 