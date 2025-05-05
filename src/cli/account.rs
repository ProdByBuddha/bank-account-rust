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

/// Display transaction history for an account
pub fn display_transaction_history(
    auth: &AuthResult,
    account_id: &str,
    limit: usize,
    offset: usize,
    start_date_str: Option<&str>,
    end_date_str: Option<&str>
) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Parse optional dates
    let start_date = if let Some(date_str) = start_date_str {
        Some(parse_date_with_default_time(date_str, 0, 0, 0)?)
    } else {
        None
    };
    
    let end_date = if let Some(date_str) = end_date_str {
        Some(parse_date_with_default_time(date_str, 23, 59, 59)?)
    } else {
        None
    };
    
    // Get transaction history
    match crate::account::transactions::get_transaction_history(
        &conn,
        auth,
        account_id,
        limit,
        offset,
        start_date,
        end_date
    ) {
        Ok(transactions) => {
            if transactions.is_empty() {
                println!("No transactions found for the specified criteria.");
                return Ok(());
            }
            
            // Check if we need to get account details to display its type and balance
            let account = match crate::account::get_account(&conn, auth, account_id) {
                Ok(account) => Some(account),
                Err(_) => None,
            };
            
            // Print account summary header
            if let Some(acc) = account {
                println!("Account: {} ({}, ${:.2})", 
                    account_id, 
                    acc.account_type.as_str(), 
                    acc.balance
                );
            } else {
                println!("Account: {}", account_id);
            }
            
            // Print date range if specified
            if start_date.is_some() || end_date.is_some() {
                println!("Period: {} to {}", 
                    start_date.map_or("All time".to_string(), |d| d.format("%Y-%m-%d").to_string()),
                    end_date.map_or("Present".to_string(), |d| d.format("%Y-%m-%d").to_string())
                );
            }
            
            println!("Showing transactions {}-{}", offset + 1, offset + transactions.len());
            println!();
            
            // Print transaction table header
            println!("{:<36} {:<12} {:<12} {:<10} {:<19}", 
                "TRANSACTION ID", "TYPE", "AMOUNT", "STATUS", "DATE"
            );
            println!("{:-<36} {:-<12} {:-<12} {:-<10} {:-<19}", 
                "", "", "", "", ""
            );
            
            // Print transactions
            for tx in &transactions {
                let tx_type = match tx.transaction_type {
                    crate::database::models::TransactionType::Deposit => "DEPOSIT",
                    crate::database::models::TransactionType::Withdrawal => "WITHDRAWAL",
                    crate::database::models::TransactionType::Transfer => "TRANSFER",
                };
                
                println!("{:<36} {:<12} ${:<11.2} {:<10} {}", 
                    tx.id,
                    tx_type,
                    tx.amount,
                    tx.status.as_str(),
                    tx.timestamp.format("%Y-%m-%d %H:%M:%S")
                );
            }
            
            // Calculate some statistics
            let total_deposits: f64 = transactions.iter()
                .filter(|t| t.transaction_type == crate::database::models::TransactionType::Deposit)
                .map(|t| t.amount)
                .sum();
                
            let total_withdrawals: f64 = transactions.iter()
                .filter(|t| t.transaction_type == crate::database::models::TransactionType::Withdrawal)
                .map(|t| t.amount)
                .sum();
                
            let total_transfers_out: f64 = transactions.iter()
                .filter(|t| t.transaction_type == crate::database::models::TransactionType::Transfer)
                .map(|t| t.amount)
                .sum();
            
            println!();
            println!("Summary:");
            println!("Total deposits: ${:.2}", total_deposits);
            println!("Total withdrawals: ${:.2}", total_withdrawals);
            println!("Total transfers: ${:.2}", total_transfers_out);
            println!("Net change: ${:.2}", total_deposits - total_withdrawals - total_transfers_out);
            
            Ok(())
        },
        Err(crate::account::transactions::TransactionError::AccountNotFound) => {
            Err(anyhow!("Account not found"))
        },
        Err(crate::account::transactions::TransactionError::AuthorizationError) => {
            Err(anyhow!("Not authorized to view transactions for this account"))
        },
        Err(e) => Err(anyhow!("Failed to retrieve transaction history: {}", e)),
    }
}

/// Helper function to parse a date string with default time components
fn parse_date_with_default_time(
    date_str: &str,
    hour: u32,
    min: u32,
    sec: u32
) -> Result<chrono::DateTime<chrono::Utc>> {
    // Try to parse YYYY-MM-DD format
    let naive_date = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .context("Invalid date format. Please use YYYY-MM-DD format.")?;
        
    // Create a NaiveDateTime with the provided time components
    let naive_datetime = naive_date.and_hms_opt(hour, min, sec)
        .ok_or_else(|| anyhow!("Invalid time values"))?;
        
    // Convert to UTC DateTime
    Ok(chrono::DateTime::from_naive_utc_and_offset(naive_datetime, chrono::Utc))
}

/// Export transaction history to a file (CSV or JSON)
pub fn export_transaction_history(
    auth: &AuthResult,
    account_id: &str,
    format: &str,
    output_path: &str,
    start_date_str: Option<&str>,
    end_date_str: Option<&str>,
    limit: usize
) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    // Parse optional dates
    let start_date = if let Some(date_str) = start_date_str {
        Some(parse_date_with_default_time(date_str, 0, 0, 0)?)
    } else {
        None
    };
    
    let end_date = if let Some(date_str) = end_date_str {
        Some(parse_date_with_default_time(date_str, 23, 59, 59)?)
    } else {
        None
    };
    
    // Get transaction history - use larger limit for export
    match crate::account::transactions::get_transaction_history(
        &conn,
        auth,
        account_id,
        limit,
        0, // no offset for export
        start_date,
        end_date
    ) {
        Ok(transactions) => {
            if transactions.is_empty() {
                println!("No transactions found for the specified criteria.");
                return Ok(());
            }
            
            match format.to_lowercase().as_str() {
                "csv" => export_to_csv(&transactions, output_path)?,
                "json" => export_to_json(&transactions, output_path)?,
                _ => return Err(anyhow!("Unsupported format. Supported formats: csv, json")),
            }
            
            println!("✅ Exported {} transactions to {}", transactions.len(), output_path);
            Ok(())
        },
        Err(crate::account::transactions::TransactionError::AccountNotFound) => {
            Err(anyhow!("Account not found"))
        },
        Err(crate::account::transactions::TransactionError::AuthorizationError) => {
            Err(anyhow!("Not authorized to view transactions for this account"))
        },
        Err(e) => Err(anyhow!("Failed to retrieve transaction history: {}", e)),
    }
}

/// Export transactions to CSV file
fn export_to_csv(transactions: &[crate::database::models::Transaction], output_path: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create(output_path)?;
    
    // Write CSV header
    writeln!(file, "ID,Type,Amount,Status,Timestamp,ReferenceID")?;
    
    // Write transaction data
    for tx in transactions {
        writeln!(
            file,
            "{},{},{:.2},{},{},{}",
            tx.id,
            tx.transaction_type.as_str(),
            tx.amount,
            tx.status.as_str(),
            tx.timestamp.to_rfc3339(),
            tx.reference_id.as_deref().unwrap_or("N/A")
        )?;
    }
    
    Ok(())
}

/// Export transactions to JSON file
fn export_to_json(transactions: &[crate::database::models::Transaction], output_path: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let json = serde_json::to_string_pretty(transactions)?;
    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;
    
    Ok(())
}

/// Retrieve and display transaction receipt
pub fn get_transaction_receipt(auth: &AuthResult, transaction_id: &str) -> Result<()> {
    // Connect to database
    let conn = crate::database::get_connection()?;
    
    match crate::account::transactions::generate_receipt_for_transaction(&conn, auth, transaction_id) {
        Ok(receipt) => {
            println!("{}", receipt);
            Ok(())
        },
        Err(crate::account::transactions::TransactionError::AuthorizationError) => {
            Err(anyhow!("Not authorized to view this transaction receipt"))
        },
        Err(e) => Err(anyhow!("Failed to retrieve transaction receipt: {}", e)),
    }
} 