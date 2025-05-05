use anyhow::{Result, Context, anyhow};
use log::{debug, info, error};
use rusqlite::Connection;
use std::time::Duration;

use crate::cli::utils::{display_spinner, read_line, read_password};
use crate::database::{self, get_connection};
use crate::user::two_factor::{self, TwoFactorError};
use crate::security::{jwt, auth::{self, AuthError}};
use crate::security::password::verify_password;
use crate::database::models::UserRole;

/// Handle user login
pub fn login(username: &str, enable_2fa: bool) -> Result<()> {
    // Get database connection
    let conn = get_connection().context("Failed to get database connection")?;
    
    // Get password
    let password = read_password("Password: ").context("Failed to read password")?;
    
    // Attempt login
    match perform_login(&conn, username, &password, enable_2fa) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Login failed: {}", e);
            println!("\n❌ Login failed: {}", e);
            Err(e)
        }
    }
}

/// Perform the login process
fn perform_login(conn: &Connection, username: &str, password: &str, enable_2fa: bool) -> Result<()> {
    println!("Authenticating...");
    
    // Get user by username
    let user = match database::get_user_by_username(conn, username) {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Security: Use generic message for non-existent users
            return Err(anyhow!("Invalid username or password"));
        },
        Err(e) => {
            return Err(anyhow!("Database error: {}", e));
        }
    };
    
    // Check if account is locked
    if user.account_locked {
        return Err(anyhow!("Account is locked. Please contact an administrator or wait for the lockout period to end."));
    }
    
    // Verify password
    let is_password_valid = match verify_password(&user.password_hash, &user.salt, password) {
        Ok(valid) => valid,
        Err(e) => {
            return Err(anyhow!("Failed to verify password: {}", e));
        }
    };
    
    // Update login attempts
    if !is_password_valid {
        // Increment failed login attempts
        let new_attempts = user.failed_login_attempts + 1;
        match database::update_failed_login_attempts(conn, &user.id, new_attempts) {
            Ok(_) => {},
            Err(e) => {
                error!("Failed to update login attempts: {}", e);
            }
        }
        
        // Check if account should be locked
        if new_attempts >= database::MAX_FAILED_LOGIN_ATTEMPTS {
            match database::lock_user_account(conn, &user.id) {
                Ok(_) => {
                    return Err(anyhow!("Too many failed login attempts. Your account has been locked."));
                },
                Err(e) => {
                    error!("Failed to lock account: {}", e);
                }
            }
        }
        
        return Err(anyhow!("Invalid username or password"));
    }
    
    // Reset failed login attempts on successful password verification
    if user.failed_login_attempts > 0 {
        match database::reset_failed_login_attempts(conn, &user.id) {
            Ok(_) => {},
            Err(e) => {
                error!("Failed to reset login attempts: {}", e);
            }
        }
    }
    
    // Check if 2FA is enabled for the user
    let tfa_verified = if user.totp_enabled {
        // If 2FA is disabled in the command line but enabled for the user, we must verify
        if !enable_2fa {
            println!("\n⚠️ Two-factor authentication is enabled for your account but was not requested.");
            println!("For security reasons, you will need to provide a verification code anyway.");
        }
        
        // Request 2FA code
        println!("\nTwo-factor authentication is enabled for your account.");
        
        // Verify TOTP code
        verify_2fa_code(conn, &user.id)?
    } else {
        // If 2FA is not enabled for the user but was requested, show a warning
        if enable_2fa {
            println!("\n⚠️ Two-factor authentication is not enabled for your account.");
            println!("You can enable it with 'secure-bank-cli user enable-2fa' after logging in.");
        }
        
        // No 2FA verification needed
        true
    };
    
    // Generate tokens - tfa_verified will determine if the token has the tfa_verified flag
    let (access_token, refresh_token) = match jwt::generate_token_pair(
        conn,
        &user.id,
        &user.username,
        &user.role,
        tfa_verified,
        None, // device info could be added in a real app
        None, // IP address could be added in a real app
    ) {
        Ok(tokens) => tokens,
        Err(e) => {
            return Err(anyhow!("Failed to generate authentication tokens: {}", e));
        }
    };
    
    // Update last login time
    match database::update_last_login(conn, &user.id) {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to update last login time: {}", e);
        }
    };
    
    // Show success message with role info
    let role_str = match user.role {
        UserRole::Admin => "administrator",
        UserRole::User => "regular user",
    };
    
    println!("\n✅ Login successful. Welcome back, {}!", user.username);
    println!("You are logged in as a {}.", role_str);
    
    // In a real application, we would store the tokens securely for future API calls
    // For this example, we'll just print a success message
    println!("Auth token generated. Valid for {} minutes.", 30); // assuming 30 min token validity
    
    // Store tokens in a secure credentials file or environment
    // This is just a placeholder - in a real app, use a secure storage mechanism
    match store_session_tokens(&access_token, &refresh_token) {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to store session tokens: {}", e);
            // Non-fatal error, continue with login
        }
    }
    
    Ok(())
}

/// Verify 2FA code
fn verify_2fa_code(conn: &Connection, user_id: &str) -> Result<bool> {
    // Try up to 3 times to get a valid code
    for attempt in 1..=3 {
        println!("\nEnter your 6-digit verification code:");
        let code = read_line(format!("Code (attempt {}/3): ", attempt).as_str())?;
        
        // Check if it's a recovery code (longer than 6 digits and contains hyphens)
        let is_recovery = code.len() > 6 && code.contains('-');
        
        if is_recovery {
            // Attempt to use recovery code
            match two_factor::use_backup_code(conn, user_id, &code) {
                Ok(true) => {
                    println!("✅ Recovery code accepted.");
                    println!("⚠️ This recovery code has been used and is no longer valid.");
                    println!("You should generate new recovery codes as soon as possible.");
                    return Ok(true);
                },
                Ok(false) | Err(TwoFactorError::InvalidBackupCode) => {
                    println!("❌ Invalid recovery code. Please try again.");
                    continue;
                },
                Err(e) => {
                    return Err(anyhow!("Failed to verify recovery code: {}", e));
                }
            }
        } else {
            // Validate format for TOTP code
            if code.len() != 6 || !code.chars().all(|c| c.is_digit(10)) {
                println!("❌ Invalid code format. The code must be 6 digits.");
                continue;
            }
            
            // Attempt to verify TOTP code
            match two_factor::verify_2fa_code(conn, user_id, &code) {
                Ok(true) => {
                    println!("✅ Verification code accepted.");
                    return Ok(true);
                },
                Ok(false) | Err(TwoFactorError::InvalidCode) => {
                    println!("❌ Invalid verification code. Please try again.");
                    continue;
                },
                Err(e) => {
                    return Err(anyhow!("Failed to verify code: {}", e));
                }
            }
        }
    }
    
    // If we get here, the user failed verification after 3 attempts
    Err(anyhow!("Failed to verify your identity after 3 attempts. Please try again later."))
}

/// Store session tokens securely
fn store_session_tokens(access_token: &str, refresh_token: &str) -> Result<()> {
    // In a real application, use a secure storage method
    // This is just a placeholder implementation
    
    // For example, you could store the tokens in:
    // 1. Encrypted file in the user's home directory
    // 2. OS keychain/keyring
    // 3. Environment variables for the current session
    
    debug!("Tokens generated and ready to use for API calls");
    
    // For this example, we'll just return success without actually storing
    Ok(())
}

/// Handle password change for the authenticated user
pub fn change_password(auth: &AuthResult) -> Result<()> {
    let user_id = &auth.user_id;
    
    println!("Changing password for your account");
    
    // Get the current password for verification
    let current_password = cli::utils::read_password("Current password: ")?;
    
    // Verify the current password
    let conn = database::get_connection()?;
    if !security::verify_password(&conn, user_id, &current_password)? {
        return Err(anyhow!("Current password is incorrect"));
    }
    
    // Get the new password
    let new_password = cli::utils::read_password("New password: ")?;
    
    // Validate password strength
    match security::validate_password_strength(&new_password) {
        Ok(_) => {},
        Err(e) => return Err(anyhow!("Password too weak: {}", e)),
    }
    
    // Confirm the new password
    let confirm_password = cli::utils::read_password("Confirm new password: ")?;
    
    if new_password != confirm_password {
        return Err(anyhow!("Passwords do not match"));
    }
    
    // Change the password
    match security::change_password(&conn, user_id, &new_password) {
        Ok(_) => {
            println!("✅ Password changed successfully!");
            Ok(())
        },
        Err(security::AuthError::TwoFactorRequired(_)) => {
            println!("⚠️ Two-factor authentication required to change your password.");
            println!("Please use 'user verify2fa --operation change_password --code YOUR_CODE' to verify.");
            Err(anyhow!("Two-factor authentication required"))
        },
        Err(e) => Err(anyhow!("Failed to change password: {}", e)),
    }
} 