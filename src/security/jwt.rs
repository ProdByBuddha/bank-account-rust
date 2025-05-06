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
use log::{debug, warn, error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config;
use crate::database;
use crate::database::models::{UserRole, Token};
use rusqlite::Connection;

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
    /// Refresh token (only for refresh tokens)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<bool>,
}

/// Token type
pub enum TokenType {
    /// Access token (default)
    Access,
    /// Refresh token
    Refresh,
}

/// Generate a JWT token for a user
pub fn generate_token(
    user_id: &str,
    username: &str,
    role: &UserRole,
    tfa_verified: bool,
    token_type: TokenType,
) -> Result<String> {
    let config = config::get_config();
    
    // Create token expiration time
    let now = Utc::now();
    let (expires_at, is_refresh) = match token_type {
        TokenType::Access => (now + Duration::minutes(config.security.token_validity), false),
        TokenType::Refresh => (now + Duration::hours(24), true), // Refresh tokens valid for 24 hours
    };
    
    // Create a unique token ID
    let token_id = Uuid::new_v4().to_string();
    
    // Create claims
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.as_str().to_string(),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        jti: token_id,
        iss: config.app_name.clone(),
        tfa_verified,
        refresh: if is_refresh { Some(true) } else { None },
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
    
    debug!("Generated JWT {} token for user {}", 
           if is_refresh { "refresh" } else { "access" }, 
           username);
    Ok(token)
}

/// Validate a JWT token and extract claims
pub fn validate_token(token: &str) -> Result<Claims> {
    let config = config::get_config();
    
    // Create validation parameters
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 60; // 60 seconds leeway for clock skew
    
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

/// Calculate a hash of the token for secure storage
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Store token in database with hash
pub fn store_token_in_db(
    conn: &Connection,
    claims: &Claims,
    device_info: Option<&str>,
    ip_address: Option<&str>,
    token: &str,
) -> Result<()> {
    // Hash the token for secure storage
    let token_hash = hash_token(token);
    
    // Create token expiration DateTime
    let expires_at = Utc::now() + Duration::seconds(claims.exp - Utc::now().timestamp());
    
    // Create token model
    let token_model = Token::new(
        claims.sub.clone(),
        token_hash,
        expires_at,
        device_info.map(String::from),
        ip_address.map(String::from),
    );
    
    // Store token in database
    database::store_token(conn, &token_model)?;
    
    debug!("Token {} stored in database for user {}", claims.jti, claims.sub);
    Ok(())
}

/// Check if a token is revoked by looking up in the database
pub fn is_token_revoked(conn: &Connection, token_id: &str) -> Result<bool> {
    // First check if token exists and is valid
    match database::is_token_valid(conn, token_id) {
        Ok(valid) => Ok(!valid), // If token is valid, it's not revoked
        Err(err) => {
            // Log the error but continue (assume token is revoked for safety)
            error!("Error checking token revocation status: {}", err);
            Ok(true)
        }
    }
}

/// Revoke a token in the database
pub fn revoke_token(conn: &Connection, token_id: &str) -> Result<bool> {
    database::revoke_token(conn, token_id)
}

/// Generate a new access token from a refresh token
pub fn refresh_access_token(conn: &Connection, refresh_token: &str) -> Result<String> {
    // Validate the refresh token first
    let claims = validate_token(refresh_token)?;
    
    // Check if this is actually a refresh token
    if claims.refresh.unwrap_or(false) == false {
        return Err(anyhow!("Not a valid refresh token"));
    }
    
    // Check if token is revoked
    if is_token_revoked(conn, &claims.jti)? {
        return Err(anyhow!("Refresh token has been revoked"));
    }
    
    // Generate a new access token
    let role = UserRole::from_str(&claims.role)
        .map_err(|e| anyhow!("Invalid role in token: {}", e))?;
    
    let access_token = generate_token(
        &claims.sub,
        &claims.username,
        &role,
        claims.tfa_verified,
        TokenType::Access,
    )?;
    
    debug!("Generated new access token via refresh for user {}", claims.username);
    Ok(access_token)
}

/// Validate token and check for revocation in database
pub fn validate_token_with_db(conn: &Connection, token: &str) -> Result<Claims> {
    // First, validate the token signature and claims
    let claims = validate_token(token)?;
    
    // Then, check if the token has been revoked
    if is_token_revoked(conn, &claims.jti)? {
        return Err(anyhow!("Token has been revoked"));
    }
    
    Ok(claims)
}

/// Revoke all tokens for a user
pub fn revoke_all_user_tokens(conn: &Connection, user_id: &str) -> Result<usize> {
    database::revoke_all_user_tokens(conn, user_id)
}

/// Generate both access and refresh tokens for a user
pub fn generate_token_pair(
    conn: &Connection,
    user_id: &str,
    username: &str,
    role: &UserRole,
    tfa_verified: bool,
    device_info: Option<&str>,
    ip_address: Option<&str>,
) -> Result<(String, String)> {
    // Generate access token
    let access_token = generate_token(
        user_id,
        username,
        role,
        tfa_verified,
        TokenType::Access,
    )?;
    
    // Generate refresh token
    let refresh_token = generate_token(
        user_id,
        username,
        role,
        tfa_verified,
        TokenType::Refresh,
    )?;
    
    // Store access token in database
    let access_claims = validate_token(&access_token)?;
    store_token_in_db(conn, &access_claims, device_info, ip_address, &access_token)?;
    
    // Store refresh token in database
    let refresh_claims = validate_token(&refresh_token)?;
    store_token_in_db(conn, &refresh_claims, device_info, ip_address, &refresh_token)?;
    
    debug!("Generated token pair for user {}", username);
    Ok((access_token, refresh_token))
}

/// Clean up expired tokens
pub fn clean_expired_tokens(conn: &Connection) -> Result<usize> {
    database::clean_expired_tokens(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    // Helper to set up a test database
    fn setup_test_db() -> (Connection, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        
        // Create tokens table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                device_info TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            )",
            [],
        ).unwrap();
        
        (conn, temp_dir)
    }
    
    #[test]
    fn test_jwt_generation_and_validation() {
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        
        // Generate token
        let token = generate_token(user_id, username, &role, tfa_verified, TokenType::Access).unwrap();
        
        // Validate token
        let claims = validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.role, role.as_str());
        assert_eq!(claims.tfa_verified, tfa_verified);
        assert!(claims.refresh.is_none());
    }
    
    #[test]
    fn test_refresh_token_generation() {
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        
        // Generate refresh token
        let token = generate_token(user_id, username, &role, tfa_verified, TokenType::Refresh).unwrap();
        
        // Validate token
        let claims = validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.role, role.as_str());
        assert_eq!(claims.tfa_verified, tfa_verified);
        assert_eq!(claims.refresh, Some(true));
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
        let jwt = generate_token(user_id, username, &role, tfa_verified, TokenType::Access).unwrap();
        
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
    
    #[test]
    fn test_token_storage_and_revocation() {
        let (conn, _temp_dir) = setup_test_db();
        
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        
        // Generate token
        let token = generate_token(user_id, username, &role, tfa_verified, TokenType::Access).unwrap();
        let claims = validate_token(&token).unwrap();
        
        // Store token
        store_token_in_db(&conn, &claims, Some("test_device"), Some("127.0.0.1"), &token).unwrap();
        
        // Check token is not revoked
        assert_eq!(is_token_revoked(&conn, &claims.jti).unwrap(), false);
        
        // Revoke token
        revoke_token(&conn, &claims.jti).unwrap();
        
        // Check token is now revoked
        assert_eq!(is_token_revoked(&conn, &claims.jti).unwrap(), true);
    }
    
    #[test]
    fn test_token_pair_generation() {
        let (conn, _temp_dir) = setup_test_db();
        
        let user_id = "test_user_id";
        let username = "testuser";
        let role = UserRole::User;
        let tfa_verified = false;
        
        // Generate token pair
        let (access_token, refresh_token) = generate_token_pair(
            &conn,
            user_id,
            username,
            &role,
            tfa_verified,
            Some("test_device"),
            Some("127.0.0.1"),
        ).unwrap();
        
        // Validate access token
        let access_claims = validate_token(&access_token).unwrap();
        assert_eq!(access_claims.sub, user_id);
        assert_eq!(access_claims.refresh, None);
        
        // Validate refresh token
        let refresh_claims = validate_token(&refresh_token).unwrap();
        assert_eq!(refresh_claims.sub, user_id);
        assert_eq!(refresh_claims.refresh, Some(true));
    }
} 