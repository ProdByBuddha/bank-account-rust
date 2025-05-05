use anyhow::{Result, Context, anyhow};
use log::{debug, info, error};
use rusqlite::Connection;
use std::time::Duration;

use crate::cli::utils::{display_qr_code, display_spinner, read_line, display_recovery_codes};
use crate::database;
use crate::user::two_factor::{self, TwoFactorError};
use crate::security::auth::{self, AuthResult};
use crate::security::{
    SensitiveOperation,
    verify_for_sensitive_operation,
};

/// Handle enabling two-factor authentication
pub fn enable_2fa(user_id: &str) -> Result<()> {
    println!("Enabling two-factor authentication...");
    println!("This will improve the security of your account by requiring a time-based authentication code during login.");
    println!("You will need an authenticator app such as Google Authenticator, Authy, or Microsoft Authenticator.");
    
    // Get a database connection
    let conn = database::get_connection()?;
    
    // Start the 2FA setup process
    match setup_2fa(&conn, user_id) {
        Ok(_) => {
            println!("\n✅ Two-factor authentication has been enabled for your account.");
            println!("You will now be required to enter a verification code when logging in.");
            Ok(())
        },
        Err(e) => {
            error!("Failed to enable 2FA: {}", e);
            println!("\n❌ Failed to enable two-factor authentication: {}", e);
            Err(e)
        }
    }
}

/// Set up two-factor authentication for a user
fn setup_2fa(conn: &Connection, user_id: &str) -> Result<()> {
    // Begin 2FA enrollment
    let uri = match two_factor::enable_2fa(conn, user_id) {
        Ok(uri_string) => uri_string,
        Err(TwoFactorError::AlreadyEnabled) => {
            return Err(anyhow!("Two-factor authentication is already enabled for your account"));
        },
        Err(e) => {
            return Err(anyhow!("Failed to initiate 2FA setup: {}", e));
        }
    };
    
    // Display the QR code
    display_qr_code(&uri)?;
    
    // Show the URI as a fallback
    println!("If you can't scan the QR code, enter this URI manually:");
    println!("{}\n", uri);
    
    // Simulate waiting for the user to scan the QR code
    display_spinner("Waiting for you to set up your authenticator app", Duration::from_secs(5))?;
    
    // Verify the code
    println!("\nTo verify your setup, enter the 6-digit code from your authenticator app:");
    
    // Try up to 3 times to get a valid code
    for attempt in 1..=3 {
        let code = read_line(format!("Code (attempt {}/3): ", attempt).as_str())?;
        
        if code.len() != 6 || !code.chars().all(|c| c.is_digit(10)) {
            println!("❌ Invalid code format. The code must be 6 digits.");
            continue;
        }
        
        match two_factor::verify_2fa_setup(conn, user_id, &code) {
            Ok(recovery_codes_vec) => {
                // Display the recovery codes
                display_recovery_codes(&recovery_codes_vec)?;
                return Ok(());
            },
            Err(TwoFactorError::InvalidCode) => {
                println!("❌ Invalid code. Please try again.");
            },
            Err(e) => {
                return Err(anyhow!("Failed to verify 2FA setup: {}", e));
            }
        }
    }
    
    // If we get here, the user failed to enter a valid code after 3 attempts
    Err(anyhow!("Failed to verify your authenticator setup after 3 attempts. Please try again later."))
}

/// Handle disabling two-factor authentication
pub fn disable_2fa(user_id: &str) -> Result<()> {
    println!("⚠️  Disabling two-factor authentication will make your account less secure.");
    println!("Are you sure you want to continue?");
    
    let confirm = read_line("Type 'confirm' to disable 2FA: ")?;
    if confirm.to_lowercase() != "confirm" {
        println!("Operation cancelled.");
        return Ok(());
    }
    
    // Get a database connection
    let conn = database::get_connection()?;
    
    // Disable 2FA
    match two_factor::disable_2fa(&conn, user_id) {
        Ok(_) => {
            println!("\n✅ Two-factor authentication has been disabled for your account.");
            Ok(())
        },
        Err(TwoFactorError::NotEnabled) => {
            println!("\nTwo-factor authentication is not enabled for your account.");
            Ok(())
        },
        Err(e) => {
            error!("Failed to disable 2FA: {}", e);
            println!("\n❌ Failed to disable two-factor authentication: {}", e);
            Err(anyhow!("Failed to disable 2FA: {}", e))
        }
    }
}

/// Generate new backup codes for a user
pub fn generate_backup_codes(user_id: &str) -> Result<()> {
    println!("Generating new backup codes...");
    println!("⚠️  This will invalidate your existing backup codes.");
    
    let confirm = read_line("Type 'confirm' to continue: ")?;
    if confirm.to_lowercase() != "confirm" {
        println!("Operation cancelled.");
        return Ok(());
    }
    
    // Get a database connection
    let conn = database::get_connection()?;
    
    // Generate new backup codes
    match two_factor::generate_backup_codes(&conn, user_id) {
        Ok(recovery_codes_vec) => {
            // Display the recovery codes
            display_recovery_codes(&recovery_codes_vec)?;
            println!("\n✅ New backup codes have been generated.");
            Ok(())
        },
        Err(TwoFactorError::NotEnabled) => {
            println!("\n❌ Two-factor authentication is not enabled for your account.");
            Err(anyhow!("Two-factor authentication is not enabled"))
        },
        Err(e) => {
            error!("Failed to generate backup codes: {}", e);
            println!("\n❌ Failed to generate backup codes: {}", e);
            Err(anyhow!("Failed to generate backup codes: {}", e))
        }
    }
}

/// Verify 2FA for a sensitive operation
pub fn verify_for_operation(user_id: &str, operation_str: &str, code: &str) -> Result<()> {
    info!("Verifying 2FA for sensitive operation: {}", operation_str);
    
    // Connect to the database
    let conn = crate::database::connect()?;
    
    // Parse the operation type
    let operation = match SensitiveOperation::from_str(operation_str) {
        Ok(op) => op,
        Err(e) => {
            return Err(anyhow!("Invalid operation type: {}", e));
        }
    };
    
    // Verify the 2FA code for the operation
    match verify_for_sensitive_operation(&conn, user_id, code, operation) {
        Ok(()) => {
            println!("✅ Verification successful for operation: {}", operation.friendly_name());
            Ok(())
        },
        Err(e) => {
            error!("2FA verification failed: {}", e);
            Err(anyhow!("2FA verification failed: {}", e))
        }
    }
} 