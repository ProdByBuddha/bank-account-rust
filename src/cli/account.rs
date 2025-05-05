use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use rusqlite::Connection;
use std::io::{self, Write};

use crate::account::{
    create_account, get_account, get_user_accounts, update_account_status, calculate_interest,
    link_accounts, AccountError,
};
use crate::database::models::{AccountType, AccountStatus};
use crate::security::auth::AuthResult;

/// Create a new account
pub fn create_new_account(auth: &AuthResult, account_type_str: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Parse account type
    let account_type = match account_type_str.to_lowercase().as_str() {
        "checking" => AccountType::Checking,
        "savings" => AccountType::Savings,
        _ => return Err(anyhow!("Invalid account type. Must be 'checking' or 'savings'.")),
    };
    
    // Ask for initial deposit
    println!("Enter initial deposit amount (leave blank for zero):");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input = input.trim().to_string();
    
    let initial_balance = if input.is_empty() {
        None
    } else {
        match input.parse::<f64>() {
            Ok(amount) if amount >= 0.0 => Some(amount),
            Ok(_) => return Err(anyhow!("Initial deposit cannot be negative.")),
            Err(_) => return Err(anyhow!("Invalid amount. Please enter a valid number.")),
        }
    };
    
    // Ask for account nickname (optional)
    println!("Enter account nickname (optional):");
    let mut nickname = String::new();
    io::stdin().read_line(&mut nickname)?;
    nickname = nickname.trim().to_string();
    
    let details = if nickname.is_empty() {
        None
    } else {
        Some(format!("{{\"nickname\":\"{}\"}}", nickname))
    };
    
    // Create account
    match create_account(&conn, auth, account_type, initial_balance, details.as_deref()) {
        Ok(account) => {
            println!("✅ Account created successfully!");
            println!("Account ID: {}", account.id);
            println!("Type: {}", account.account_type.as_str());
            println!("Balance: ${:.2}", account.balance);
            println!("Status: {}", account.status.as_str());
            Ok(())
        },
        Err(AccountError::TwoFactorRequired(_)) => {
            println!("⚠️ Two-factor authentication required to create an account.");
            println!("Please use 'user verify2fa --operation create_account --code YOUR_CODE' to verify.");
            Err(anyhow!("Two-factor authentication required"))
        },
        Err(e) => Err(anyhow!("Failed to create account: {}", e)),
    }
}

/// Get account details
pub fn get_account_details(auth: &AuthResult, account_id: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Get account details
    match get_account(&conn, auth, account_id) {
        Ok(account) => {
            println!("Account Details:");
            println!("ID: {}", account.id);
            println!("User ID: {}", account.user_id);
            println!("Type: {}", account.account_type.as_str());
            println!("Balance: ${:.2}", account.balance);
            println!("Status: {}", account.status.as_str());
            println!("Created: {}", account.created_at);
            println!("Updated: {}", account.updated_at);
            
            if let Some(details) = account.encrypted_details {
                println!("Details: {}", details);
            }
            
            Ok(())
        },
        Err(AccountError::NotFound) => Err(anyhow!("Account not found")),
        Err(AccountError::AuthorizationError) => Err(anyhow!("Not authorized to view this account")),
        Err(e) => Err(anyhow!("Failed to get account details: {}", e)),
    }
}

/// List user accounts
pub fn list_accounts(auth: &AuthResult, target_user_id: Option<&str>) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Get accounts
    match get_user_accounts(&conn, auth, target_user_id) {
        Ok(accounts) => {
            if accounts.is_empty() {
                println!("No accounts found.");
                return Ok(());
            }
            
            println!("{:<36} {:<10} {:<12} {:<10}", "ID", "TYPE", "BALANCE", "STATUS");
            println!("{:-<36} {:-<10} {:-<12} {:-<10}", "", "", "", "");
            
            for account in accounts {
                println!("{:<36} {:<10} ${:<11.2} {:<10}",
                    account.id,
                    account.account_type.as_str(),
                    account.balance,
                    account.status.as_str()
                );
            }
            
            Ok(())
        },
        Err(AccountError::AuthorizationError) => Err(anyhow!("Not authorized to view these accounts")),
        Err(e) => Err(anyhow!("Failed to list accounts: {}", e)),
    }
}

/// Update account status
pub fn update_status(auth: &AuthResult, account_id: &str, status_str: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Parse status
    let new_status = match status_str.to_lowercase().as_str() {
        "active" => AccountStatus::Active,
        "suspended" => AccountStatus::Suspended,
        "closed" => AccountStatus::Closed,
        _ => return Err(anyhow!("Invalid status. Must be 'active', 'suspended', or 'closed'.")),
    };
    
    // Get current account status
    let current_account = match get_account(&conn, auth, account_id) {
        Ok(account) => account,
        Err(AccountError::NotFound) => return Err(anyhow!("Account not found")),
        Err(AccountError::AuthorizationError) => return Err(anyhow!("Not authorized to view this account")),
        Err(e) => return Err(anyhow!("Failed to get account details: {}", e)),
    };
    
    // Check if status is already the desired one
    if current_account.status == new_status {
        println!("Account is already in '{}' status.", new_status.as_str());
        return Ok(());
    }
    
    // Update status
    match update_account_status(&conn, auth, account_id, new_status) {
        Ok(()) => {
            println!("✅ Account status updated successfully!");
            println!("Previous status: {}", current_account.status.as_str());
            println!("New status: {}", new_status.as_str());
            Ok(())
        },
        Err(AccountError::TwoFactorRequired(_)) => {
            println!("⚠️ Two-factor authentication required to update account status.");
            println!("Please use 'user verify2fa --operation update_account_status --code YOUR_CODE' to verify.");
            Err(anyhow!("Two-factor authentication required"))
        },
        Err(e) => Err(anyhow!("Failed to update account status: {}", e)),
    }
}

/// Calculate interest for a savings account
pub fn calc_interest(auth: &AuthResult, account_id: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Calculate interest
    match calculate_interest(&conn, auth, account_id) {
        Ok(interest) => {
            println!("Daily interest calculation:");
            println!("Account ID: {}", account_id);
            println!("Interest amount: ${:.4}", interest);
            println!("Note: This is a simulation and does not modify the account balance.");
            
            // Get current balance
            match get_account(&conn, auth, account_id) {
                Ok(account) => {
                    println!("Current balance: ${:.2}", account.balance);
                    println!("Annual interest rate: 2.0%");
                    
                    // Calculate annual interest
                    let annual_interest = account.balance * 0.02;
                    println!("Projected annual interest: ${:.2}", annual_interest);
                },
                Err(_) => {}, // Already handled above
            }
            
            Ok(())
        },
        Err(AccountError::NotFound) => Err(anyhow!("Account not found")),
        Err(AccountError::AuthorizationError) => Err(anyhow!("Not authorized to view this account")),
        Err(AccountError::InvalidParameters(msg)) => Err(anyhow!("{}", msg)),
        Err(e) => Err(anyhow!("Failed to calculate interest: {}", e)),
    }
}

/// Link accounts
pub fn link_user_accounts(auth: &AuthResult, primary_account_id: &str, accounts_to_link: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Parse account IDs
    let linked_account_ids: Vec<&str> = accounts_to_link.split(',').map(|s| s.trim()).collect();
    
    if linked_account_ids.is_empty() {
        return Err(anyhow!("No accounts to link. Please provide comma-separated account IDs."));
    }
    
    // Validate primary account
    match get_account(&conn, auth, primary_account_id) {
        Ok(_) => {},
        Err(AccountError::NotFound) => return Err(anyhow!("Primary account not found")),
        Err(AccountError::AuthorizationError) => return Err(anyhow!("Not authorized to manage this account")),
        Err(e) => return Err(anyhow!("Error checking primary account: {}", e)),
    }
    
    // Validate all linked accounts
    for &linked_id in &linked_account_ids {
        match get_account(&conn, auth, linked_id) {
            Ok(_) => {},
            Err(AccountError::NotFound) => return Err(anyhow!("Linked account not found: {}", linked_id)),
            Err(AccountError::AuthorizationError) => return Err(anyhow!("Not authorized to link account: {}", linked_id)),
            Err(e) => return Err(anyhow!("Error checking linked account {}: {}", linked_id, e)),
        }
    }
    
    // Link accounts
    match link_accounts(&conn, auth, primary_account_id, &linked_account_ids) {
        Ok(()) => {
            println!("✅ Accounts linked successfully!");
            println!("Primary account: {}", primary_account_id);
            println!("Linked accounts: {}", accounts_to_link);
            Ok(())
        },
        Err(AccountError::TwoFactorRequired(_)) => {
            println!("⚠️ Two-factor authentication required to link accounts.");
            println!("Please use 'user verify2fa --operation link_accounts --code YOUR_CODE' to verify.");
            Err(anyhow!("Two-factor authentication required"))
        },
        Err(e) => Err(anyhow!("Failed to link accounts: {}", e)),
    }
} 