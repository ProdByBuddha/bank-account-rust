use anyhow::{Context, Result, anyhow};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use josekit::{
    jwe::{JweDecrypter, JweEncrypter, JweHeader},
    jwt::JwtPayload,
    JoseError,
};
use josekit::jwe::alg::rsaes::{RsaesJweAlgorithm, RsaesJweDecrypter, RsaesJweEncrypter};
use josekit::jwe::enc::aescbc::{A256CbcHsEncryption, A256CbcHs512};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config;
use crate::database::models::UserRole;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// User role
    pub role: String,
    /// Issued at (timestamp)
    pub iat: i64,
    /// Expiration time
    pub exp: i64,
    /// JWT ID (unique identifier for this token)
    pub jti: String,
    /// Issuer
    pub iss: String,
    /// Two-factor authentication verified
    #[serde(default)]
    pub tfa_verified: bool,
}

/// Generate a JWT token for a user
pub fn generate_token(
    user_id: &str,
    username: &str,
    role: &UserRole,
    tfa_verified: bool,
) -> Result<String> {
    let config = config::get_config();
    
    // Create token expiration time
    let now = Utc::now();
    let expires_at = now + Duration::minutes(config.security.token_validity);
    
    // Create claims
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.as_str().to_string(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        jti: Uuid::new_v4().to_string(),
        iss: config.app_name.clone(),
        tfa_verified,
    };
    
    // Create JWT header
    let header = Header::new(Algorithm::HS256);
    
    // Encode the token
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(config.security.jwt_secret.as_bytes()),
    )
    .context("Failed to generate JWT token")?;
    
    debug!("Generated JWT token for user {}", username);
    Ok(token)
}

/// Validate a JWT token and extract claims
pub fn validate_token(token: &str) -> Result<Claims> {
    let config = config::get_config();
    
    // Create validation parameters
    let validation = Validation::new(Algorithm::HS256);
    
    // Decode and validate the token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.security.jwt_secret.as_bytes()),
        &validation,
    )
    .context("Failed to validate JWT token")?;
    
    Ok(token_data.claims)
}

/// Create a JWE encrypted token
pub fn encrypt_token(token: &str, public_key_pem: &str) -> Result<String> {
    // Create JWE header
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_type("JWT");
    
    // Create RSA encrypter with A256CBC-HS512 encryption
    let alg = RsaesJweAlgorithm::Rsa1_5;
    let enc = A256CbcHs512;
    
    let encrypter = RsaesJweEncrypter::new_from_pem(public_key_pem, alg)
        .context("Failed to create JWE encrypter from public key")?;
    
    // Create JWE from JWT
    let jwe = josekit::jwe::serialize_compact(token.as_bytes(), &header, &encrypter, &enc)
        .context("Failed to create JWE from JWT")?;
    
    debug!("Encrypted JWT token to JWE");
    Ok(jwe)
}

/// Decrypt a JWE token
pub fn decrypt_token(jwe: &str, private_key_pem: &str) -> Result<String> {
    // Create RSA decrypter
    let alg = RsaesJweAlgorithm::Rsa1_5;
    let decrypter = RsaesJweDecrypter::new_from_pem(private_key_pem, alg)
        .context("Failed to create JWE decrypter from private key")?;
    
    // Decrypt JWE to get JWT
    let (jwt, _header) = josekit::jwe::deserialize_compact(jwe, &decrypter)
        .context("Failed to decrypt JWE token")?;
    
    // Convert bytes to string
    let jwt_str = String::from_utf8(jwt).context("Failed to convert JWT bytes to string")?;
    
    debug!("Decrypted JWE token to JWT");
    Ok(jwt_str)
}

/// Generate RSA key pair for JWE encryption/decryption
pub fn generate_rsa_key_pair() -> Result<(String, String)> {
    // In a real application, you would use a proper key management system
    // This is just a basic example
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey}};
    use rand::rngs::OsRng;
    
    // Generate a 2048-bit RSA key pair
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .context("Failed to generate RSA private key")?;
    let public_key = RsaPublicKey::from(&private_key);
    
    // Convert to PEM format
    let private_key_pem = private_key.to_pkcs8_pem(Default::default())
        .context("Failed to convert private key to PEM")?
        .to_string();
    
    let public_key_pem = public_key.to_public_key_pem()
        .context("Failed to convert public key to PEM")?;
    
    Ok((private_key_pem, public_key_pem))
}

/// Store token hash in database
pub fn store_token(
    user_id: &str,
    token_id: &str,
    expires_at: &chrono::DateTime<Utc>,
    device_info: Option<&str>,
    ip_address: Option<&str>,
) -> Result<()> {
    // TODO: Implement token storage in database
    // This would create a record of valid tokens for better security
    // and enable token revocation
    
    debug!("Token {} for user {} stored in database", token_id, user_id);
    Ok(())
}

/// Check if a token is revoked
pub fn is_token_revoked(token_id: &str) -> Result<bool> {
    // TODO: Implement token revocation check in database
    // This would check if a token has been explicitly revoked
    
    Ok(false)
}

/// Revoke a token
pub fn revoke_token(token_id: &str) -> Result<()> {
    // TODO: Implement token revocation in database
    // This would mark a token as revoked to prevent its use
    
    debug!("Token {} revoked", token_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_jwt_generation_and_validation() {
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        
        // Generate token
        let token = generate_token(user_id, username, &role, tfa_verified).unwrap();
        
        // Validate token
        let claims = validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.role, role.as_str());
        assert_eq!(claims.tfa_verified, tfa_verified);
    }
    
    #[test]
    fn test_jwe_encryption_and_decryption() {
        // Generate RSA key pair
        let (private_key, public_key) = generate_rsa_key_pair().unwrap();
        
        // Generate a JWT token
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        let jwt = generate_token(user_id, username, &role, tfa_verified).unwrap();
        
        // Encrypt the token
        let jwe = encrypt_token(&jwt, &public_key).unwrap();
        
        // Decrypt the token
        let decrypted_jwt = decrypt_token(&jwe, &private_key).unwrap();
        
        // Verify the decrypted token
        assert_eq!(jwt, decrypted_jwt);
        
        // Validate the decrypted token
        let claims = validate_token(&decrypted_jwt).unwrap();
        assert_eq!(claims.sub, user_id);
    }
} 