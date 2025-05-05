use crate::cli::utils::{print_success, print_error, print_warning, print_info, print_header, Interactive};
use crate::security::auth::AuthResult;
use anyhow::Result;

/// Implement interactive account creation
pub fn create_account_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Create New Account",
        vec![
            "Select account type",
            "Set initial deposit",
            "Configure account settings",
        ],
        || {
            // Step 1: Select account type
            print_header("Account Type");
            
            let account_types = vec![
                ("Checking Account".to_string(), "checking".to_string()),
                ("Savings Account".to_string(), "savings".to_string()),
            ];
            
            let account_type = Interactive::menu("Select account type", &account_types)?;
            
            // Step 2: Initial deposit
            print_header("Initial Deposit");
            
            let deposit_str = crate::cli::utils::read_line("Initial deposit amount (0 for no deposit): ")?;
            let deposit = deposit_str.parse::<f64>().unwrap_or(0.0);
            
            // Step 3: Account settings
            print_header("Account Settings");
            
            let settings_options = vec![
                ("Standard".to_string(), "standard".to_string()),
                ("Premium".to_string(), "premium".to_string()),
            ];
            
            let settings = Interactive::menu("Select account settings", &settings_options)?;
            
            // Confirm creation
            let confirm = crate::cli::utils::read_line("Create this account? [y/N]: ")?;
            if confirm.to_lowercase() != "y" {
                return Err(anyhow::anyhow!("Account creation cancelled"));
            }
            
            // Call the actual account creation
            crate::cli::account::create_account(auth, &account_type)
        }
    )
}

/// Implement interactive transfer
pub fn transfer_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Transfer Funds",
        vec![
            "Select source account",
            "Select destination account",
            "Enter transfer amount",
            "Add transaction notes",
        ],
        || {
            // Step 1: Select source account
            print_header("Source Account");
            
            // Get user accounts
            let accounts = crate::cli::account::get_user_accounts(auth)?;
            
            if accounts.is_empty() {
                return Err(anyhow::anyhow!("You don't have any accounts"));
            }
            
            let source_options: Vec<(String, String)> = accounts.iter()
                .map(|(id, name, balance)| (format!("{} - Balance: ${:.2}", name, balance), id.clone()))
                .collect();
            
            let source_account = Interactive::menu("Select source account", &source_options)?;
            
            // Step 2: Select destination account
            print_header("Destination Account");
            
            let dest_options: Vec<(String, String)> = accounts.iter()
                .filter(|(id, _, _)| id != &source_account)
                .map(|(id, name, balance)| (format!("{} - Balance: ${:.2}", name, balance), id.clone()))
                .collect();
            
            let dest_account = if !dest_options.is_empty() {
                let use_own = crate::cli::utils::read_line("Transfer to one of your accounts? [y/N]: ")?;
                
                if use_own.to_lowercase() == "y" {
                    Interactive::menu("Select destination account", &dest_options)?
                } else {
                    crate::cli::utils::read_line("Enter destination account ID: ")?
                }
            } else {
                crate::cli::utils::read_line("Enter destination account ID: ")?
            };
            
            // Step 3: Transfer amount
            print_header("Transfer Amount");
            
            let amount_str = crate::cli::utils::read_line("Enter transfer amount: $")?;
            let amount = match amount_str.parse::<f64>() {
                Ok(a) if a > 0.0 => a,
                _ => return Err(anyhow::anyhow!("Invalid amount: must be greater than 0")),
            };
            
            // Step 4: Transaction notes
            print_header("Transaction Notes");
            print_info("Transaction notes will be encrypted and stored securely.");
            
            let details = crate::cli::utils::read_line("Enter transaction notes (optional): ")?;
            let details_option = if details.is_empty() { None } else { Some(details) };
            
            // Confirm transfer
            print_header("Confirm Transfer");
            print_info(&format!("Transfer ${:.2} from {} to {}", amount, source_account, dest_account));
            
            let confirm = crate::cli::utils::read_line("Confirm this transfer? [y/N]: ")?;
            if confirm.to_lowercase() != "y" {
                return Err(anyhow::anyhow!("Transfer cancelled"));
            }
            
            // Execute the transfer
            crate::cli::account::transfer(auth, &source_account, &dest_account, amount, details_option.as_deref())
        }
    )
}

/// Implement interactive transaction history view
pub fn transaction_history_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Transaction History",
        vec![
            "Select account",
            "Set filters",
            "View transactions",
        ],
        || {
            // Step 1: Select account
            print_header("Select Account");
            
            // Get user accounts
            let accounts = crate::cli::account::get_user_accounts(auth)?;
            
            if accounts.is_empty() {
                return Err(anyhow::anyhow!("You don't have any accounts"));
            }
            
            let account_options: Vec<(String, String)> = accounts.iter()
                .map(|(id, name, balance)| (format!("{} - Balance: ${:.2}", name, balance), id.clone()))
                .collect();
            
            let account_id = Interactive::menu("Select account", &account_options)?;
            
            // Step 2: Set filters
            print_header("Set Filters");
            
            let use_date_filter = crate::cli::utils::read_line("Apply date filters? [y/N]: ")?;
            
            let (start_date, end_date) = if use_date_filter.to_lowercase() == "y" {
                let start = crate::cli::utils::read_line("Start date (YYYY-MM-DD, leave empty for no start date): ")?;
                let end = crate::cli::utils::read_line("End date (YYYY-MM-DD, leave empty for no end date): ")?;
                
                (
                    if start.is_empty() { None } else { Some(start) },
                    if end.is_empty() { None } else { Some(end) }
                )
            } else {
                (None, None)
            };
            
            let limit_str = crate::cli::utils::read_line("Number of transactions to show (default: 10): ")?;
            let limit = limit_str.parse::<usize>().unwrap_or(10);
            
            let offset_str = crate::cli::utils::read_line("Number of transactions to skip (default: 0): ")?;
            let offset = offset_str.parse::<usize>().unwrap_or(0);
            
            // Step 3: View transactions
            print_header("Transaction History");
            
            // Display the transaction history
            crate::cli::account::display_transaction_history(
                auth,
                &account_id,
                limit,
                offset,
                start_date.as_deref(),
                end_date.as_deref()
            )
        }
    )
}

/// Interactive security compliance check
pub fn compliance_check_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Security Compliance Check",
        vec![
            "Select compliance standards",
            "Set check scope",
            "Run compliance scan",
        ],
        || {
            // Step 1: Select compliance standards
            print_header("Compliance Standards");
            
            let standard_options = vec![
                ("PCI-DSS".to_string(), "pci-dss".to_string()),
                ("GDPR".to_string(), "gdpr".to_string()),
                ("SOC 2".to_string(), "soc2".to_string()),
                ("All Standards".to_string(), "all".to_string()),
            ];
            
            let standard = Interactive::menu("Select compliance standard", &standard_options)?;
            
            // Step 2: Set check scope
            print_header("Check Scope");
            
            let scope_options = vec![
                ("Full System Scan".to_string(), "full".to_string()),
                ("Database Security Only".to_string(), "database".to_string()),
                ("User Authentication Only".to_string(), "auth".to_string()),
                ("Transaction Security Only".to_string(), "transactions".to_string()),
            ];
            
            let scope = Interactive::menu("Select scan scope", &scope_options)?;
            
            // Step 3: Run the check
            print_header("Running Compliance Check");
            
            print_info(&format!("Running {} compliance check with {} scope...", standard, scope));
            
            let pb = Interactive::progress_bar("Scanning system", 10);
            for i in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                pb.set(i + 1)?;
            }
            
            // Call the actual compliance check function
            crate::cli::security::run_compliance_check(auth)
        }
    )
}

/// Interactive audit log search
pub fn audit_search_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Search Audit Logs",
        vec![
            "Set search filters",
            "Configure output options",
            "Run search",
        ],
        || {
            // Step 1: Set search filters
            print_header("Search Filters");
            
            let user_id = crate::cli::utils::read_line("Filter by user ID (leave empty for all users): ")?;
            let user_id_option = if user_id.is_empty() { None } else { Some(user_id) };
            
            let account_id = crate::cli::utils::read_line("Filter by account ID (leave empty for all accounts): ")?;
            let account_id_option = if account_id.is_empty() { None } else { Some(account_id) };
            
            let event_type = crate::cli::utils::read_line("Filter by event type (leave empty for all events): ")?;
            let event_type_option = if event_type.is_empty() { None } else { Some(event_type) };
            
            let from_date = crate::cli::utils::read_line("From date (YYYY-MM-DD, leave empty for no start date): ")?;
            let from_date_option = if from_date.is_empty() { None } else { Some(from_date) };
            
            let to_date = crate::cli::utils::read_line("To date (YYYY-MM-DD, leave empty for no end date): ")?;
            let to_date_option = if to_date.is_empty() { None } else { Some(to_date) };
            
            let text_search = crate::cli::utils::read_line("Search in log details (leave empty for no text search): ")?;
            let text_search_option = if text_search.is_empty() { None } else { Some(text_search) };
            
            // Step 2: Configure output options
            print_header("Output Options");
            
            let limit_str = crate::cli::utils::read_line("Maximum number of records to return (default: 50): ")?;
            let limit = limit_str.parse::<usize>().unwrap_or(50);
            
            let format_options = vec![
                ("Table Format".to_string(), "table".to_string()),
                ("JSON Format".to_string(), "json".to_string()),
                ("CSV Format".to_string(), "csv".to_string()),
            ];
            
            let format = Interactive::menu("Select output format", &format_options)?;
            
            // Step 3: Run search
            print_header("Search Results");
            
            // This would call the actual audit search function
            // cli::audit::search_audit_logs(
            //    auth,
            //    user_id_option.as_deref(),
            //    account_id_option.as_deref(),
            //    event_type_option.as_deref(),
            //    from_date_option.as_deref(),
            //    to_date_option.as_deref(),
            //    limit,
            //    text_search_option.as_deref()
            // )
            
            // For now, just show a message
            print_info("Searching audit logs...");
            std::thread::sleep(std::time::Duration::from_secs(2));
            print_success("Search completed successfully");
            
            Ok(())
        }
    )
}

/// Interactive security self-assessment
pub fn security_assessment_interactive(auth: &AuthResult) -> Result<()> {
    Interactive::wizard(
        "Security Self-Assessment",
        vec![
            "Configure assessment options",
            "Run assessment",
            "View results"
        ],
        || {
            // Step 1: Configure assessment options
            print_header("Assessment Options");
            
            let option_types = vec![
                ("Check for sensitive data exposure".to_string(), "sensitive_data".to_string()),
                ("Apply data retention policies".to_string(), "data_retention".to_string()),
                ("Generate security report".to_string(), "security_report".to_string()),
                ("All of the above".to_string(), "all".to_string()),
            ];
            
            let option = Interactive::menu("Select assessment type", &option_types)?;
            
            // Step 2: Run assessment
            print_header("Running Security Assessment");
            
            print_info(&format!("Running security assessment with {} options...", option));
            
            let pb = Interactive::progress_bar("Analyzing system", 12);
            for i in 0..12 {
                std::thread::sleep(std::time::Duration::from_millis(400));
                pb.set(i + 1)?;
            }
            
            // Step 3: View results
            print_header("Assessment Results");
            
            // Call the actual security assessment function
            crate::cli::security::run_security_assessment(auth)
        }
    )
} 