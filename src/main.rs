use clap::{Parser, Subcommand};
use dotenv::dotenv;
use env_logger::Env;
use log::{info, error};
use std::process;

mod user;
mod account;
mod security;
mod audit;
mod database;
mod cli;
mod config;

/// Secure Banking CLI - A security-focused terminal-based banking system
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Sets the configuration file
    #[clap(short, long, value_name = "FILE", default_value = "config.toml")]
    config: String,

    /// Turn debugging information on
    #[clap(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the system and create the admin user
    Init {
        /// Admin username
        #[clap(long, default_value = "admin")]
        username: String,
    },
    
    /// Login to the system
    Login {
        /// Username
        #[clap(short, long)]
        username: String,
        
        /// Use 2FA if enabled
        #[clap(short, long)]
        twofa: bool,
    },
    
    /// User management commands
    User {
        #[clap(subcommand)]
        command: UserCommands,
    },
    
    /// Account management commands
    Account {
        #[clap(subcommand)]
        command: AccountCommands,
    },
    
    /// Security management commands
    Security {
        #[clap(subcommand)]
        command: SecurityCommands,
    },
    
    /// Audit trail and logging commands
    Audit {
        #[clap(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// Create a new user
    Create {
        /// Username
        #[clap(short, long)]
        username: String,
        
        /// Role (admin or user)
        #[clap(short, long, default_value = "user")]
        role: String,
    },
    
    /// Change user password
    ChangePassword {},
    
    /// Enable two-factor authentication
    Enable2FA {},
    
    /// Disable two-factor authentication
    Disable2FA {},
    
    /// Generate new 2FA backup codes
    GenBackupCodes {},
    
    /// Verify 2FA code for a sensitive operation
    Verify2FA {
        /// The operation type to verify (transfer_funds, change_password, etc.)
        #[arg(long, short = 'o')]
        operation: String,
        
        /// The verification code from your authenticator app
        #[arg(long, short = 'c')]
        code: String,
    },
    
    /// List all users and their roles
    ListUsers {},
    
    /// Change a user's role
    ChangeRole {
        /// User ID to change role for
        #[clap(long)]
        user_id: String,
        
        /// New role (admin or user)
        #[clap(long)]
        role: String,
    },
    
    /// List all available permissions for each role
    ListPermissions {},
    
    /// Check if the current user has a specific permission
    CheckPermission {
        /// Permission to check
        #[clap(long)]
        permission: String,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Create a new account
    Create {
        /// Account type (checking or savings)
        #[clap(short, long)]
        r#type: String,
    },
    
    /// Deposit funds
    Deposit {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Amount to deposit
        #[clap(short, long)]
        amount: f64,
        
        /// Transaction details (will be encrypted)
        #[clap(long)]
        details: Option<String>,
    },
    
    /// Withdraw funds
    Withdraw {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Amount to withdraw
        #[clap(short, long)]
        amount: f64,
        
        /// Transaction details (will be encrypted)
        #[clap(long)]
        details: Option<String>,
    },
    
    /// Transfer funds between accounts
    Transfer {
        /// Source account ID
        #[clap(long)]
        from: String,
        
        /// Destination account ID
        #[clap(long)]
        to: String,
        
        /// Amount to transfer
        #[clap(short, long)]
        amount: f64,
        
        /// Transaction details (will be encrypted)
        #[clap(long)]
        details: Option<String>,
    },
    
    /// Get account balance
    Balance {
        /// Account ID
        #[clap(long)]
        id: String,
    },
    
    /// View transaction history
    History {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Number of transactions to show
        #[clap(short, long, default_value = "10")]
        limit: usize,
        
        /// Number of transactions to skip
        #[clap(long, default_value = "0")]
        offset: usize,
        
        /// Start date (YYYY-MM-DD)
        #[clap(long)]
        start_date: Option<String>,
        
        /// End date (YYYY-MM-DD)
        #[clap(long)]
        end_date: Option<String>,
    },
    
    /// Get a transaction receipt
    Receipt {
        /// Transaction ID
        #[clap(long)]
        id: String,
    },
    
    /// Export transaction history to a file
    Export {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Output file path
        #[clap(short, long)]
        output: String,
        
        /// Export format (csv or json)
        #[clap(short, long, default_value = "csv")]
        format: String,
        
        /// Start date (YYYY-MM-DD)
        #[clap(long)]
        start_date: Option<String>,
        
        /// End date (YYYY-MM-DD)
        #[clap(long)]
        end_date: Option<String>,
        
        /// Maximum number of transactions to export
        #[clap(long, default_value = "1000")]
        limit: usize,
    },
    
    /// Schedule a future transaction
    Schedule {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Transaction type (deposit, withdrawal, transfer)
        #[clap(long)]
        r#type: String,
        
        /// Amount 
        #[clap(short, long)]
        amount: f64,
        
        /// Scheduled date (YYYY-MM-DD HH:MM:SS)
        #[clap(long)]
        date: String,
        
        /// Destination account ID (for transfers)
        #[clap(long)]
        to: Option<String>,
        
        /// Transaction details (will be encrypted)
        #[clap(long)]
        details: Option<String>,
    },
    
    /// Create a recurring transaction
    Recurring {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Transaction type (deposit, withdrawal, transfer)
        #[clap(long)]
        r#type: String,
        
        /// Amount
        #[clap(short, long)]
        amount: f64,
        
        /// Frequency (daily, weekly, biweekly, monthly, quarterly, yearly)
        #[clap(long)]
        frequency: String,
        
        /// Start date (YYYY-MM-DD)
        #[clap(long)]
        start_date: String,
        
        /// End date (YYYY-MM-DD)
        #[clap(long)]
        end_date: Option<String>,
        
        /// Destination account ID (for transfers)
        #[clap(long)]
        to: Option<String>,
        
        /// Transaction details (will be encrypted)
        #[clap(long)]
        details: Option<String>,
    },
    
    /// Cancel a scheduled transaction
    CancelScheduled {
        /// Scheduled transaction ID
        #[clap(long)]
        id: String,
    },
    
    /// Cancel a recurring transaction
    CancelRecurring {
        /// Recurring transaction ID
        #[clap(long)]
        id: String,
    },
    
    /// Run the scheduler to process pending scheduled transactions
    ProcessScheduled {},
    
    /// List all accounts
    List {
        /// User ID (admin only)
        #[clap(long)]
        user_id: Option<String>,
    },
    
    /// Update account status
    Status {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// New status (active, suspended, closed)
        #[clap(long)]
        status: String,
    },
    
    /// Calculate interest for a savings account
    Interest {
        /// Account ID
        #[clap(long)]
        id: String,
    },
    
    /// Link accounts
    Link {
        /// Primary account ID
        #[clap(long)]
        primary: String,
        
        /// Comma-separated list of account IDs to link
        #[clap(long)]
        accounts: String,
    },
}

#[derive(Subcommand)]
enum SecurityCommands {
    /// Run a compliance check
    ComplianceCheck {},
    
    /// Create an encrypted backup
    Backup {
        /// Output file
        #[clap(short, long)]
        output: String,
    },
    
    /// Restore from an encrypted backup
    Restore {
        /// Input file
        #[clap(short, long)]
        input: String,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Search audit logs
    Search {
        /// Filter by user ID
        #[clap(long)]
        user_id: Option<String>,
        
        /// Filter by account ID
        #[clap(long)]
        account_id: Option<String>,
        
        /// Filter by event type
        #[clap(long)]
        event_type: Option<String>,
        
        /// Start date in YYYY-MM-DD format
        #[clap(long)]
        from_date: Option<String>,
        
        /// End date in YYYY-MM-DD format
        #[clap(long)]
        to_date: Option<String>,
        
        /// Maximum number of records to return
        #[clap(long, short, default_value = "50")]
        limit: usize,
        
        /// Search in log details text
        #[clap(long)]
        text: Option<String>,
    },
    
    /// Rotate audit logs if they exceed the maximum size
    Rotate {},
    
    /// Purge old audit logs based on retention policy
    Purge {
        /// Confirm purging without additional prompt
        #[clap(long)]
        confirm: bool,
    },
    
    /// Encrypt sensitive information in audit logs
    EncryptSensitive {},
    
    /// Export audit logs to a file
    Export {
        /// Output file path
        #[clap(long, short)]
        output: String,
        
        /// Output format (json or csv)
        #[clap(long, short, default_value = "json")]
        format: String,
        
        /// Filter by user ID
        #[clap(long)]
        user_id: Option<String>,
        
        /// Start date in YYYY-MM-DD format
        #[clap(long)]
        from_date: Option<String>,
        
        /// End date in YYYY-MM-DD format
        #[clap(long)]
        to_date: Option<String>,
    },
    
    /// Decrypt an encrypted audit log archive
    Decrypt {
        /// Input encrypted file path
        #[clap(long, short)]
        input: String,
        
        /// Output file path
        #[clap(long, short)]
        output: String,
    },
    
    /// Check for suspicious activity
    Suspicious {
        /// User ID to check
        #[clap(long)]
        user_id: String,
    },
}

// Get authentication token (placeholder function)
// In a real application, this would retrieve the stored token
fn get_auth_token() -> Option<String> {
    // In a real application, you would retrieve the token from:
    // - Secure storage (keychain, encrypted file, etc.)
    // - Environment variables
    // - Memory during the current session
    
    // For this example, we'll simulate a token
    // This is just a placeholder - in a real app, the token would be retrieved securely
    
    // TODO: Implement proper token retrieval from secure storage
    Some("dummy_token".to_string())
}

fn main() {
    // Load environment variables from .env file
    dotenv().ok();
    
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Set log level based on verbosity
    match cli.debug {
        0 => log::set_max_level(log::LevelFilter::Info),
        1 => log::set_max_level(log::LevelFilter::Debug),
        _ => log::set_max_level(log::LevelFilter::Trace),
    }
    
    info!("Starting Secure Banking CLI");
    
    // Initialize config from the provided file
    match config::load_config(&cli.config) {
        Ok(_) => {
            info!("Configuration loaded successfully");
        }
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            process::exit(1);
        }
    }
    
    // Initialize database if it doesn't exist
    match database::initialize() {
        Ok(_) => {
            info!("Database initialized successfully");
        }
        Err(err) => {
            error!("Failed to initialize database: {}", err);
            process::exit(1);
        }
    }
    
    // Process the command
    match &cli.command {
        Commands::Init { username } => {
            println!("Initializing system with admin user: {}", username);
            // TODO: Implement initialization logic
        }
        Commands::Login { username, twofa } => {
            println!("Logging in as user: {}", username);
            
            match cli::auth::login(username, *twofa) {
                Ok(auth) => {},
                Err(err) => {
                    error!("Error logging in: {}", err);
                    process::exit(1);
                }
            }
        }
        Commands::User { command } => {
            match command {
                UserCommands::Create { username, role } => {
                    println!("Creating new user: {} with role: {}", username, role);
                    // TODO: Implement user creation
                }
                UserCommands::ChangePassword {} => {
                    println!("Changing password");
                    // TODO: Implement password change
                }
                UserCommands::Enable2FA {} => {
                    // Mock user ID (in a real app, this would be obtained from the authenticated session)
                    let user_id = "test-user";
                    
                    match cli::user::enable_2fa(user_id) {
                        Ok(_) => {},
                        Err(err) => {
                            error!("Error enabling 2FA: {}", err);
                            process::exit(1);
                        }
                    }
                }
                UserCommands::Disable2FA {} => {
                    // Mock user ID (in a real app, this would be obtained from the authenticated session)
                    let user_id = "test-user";
                    
                    match cli::user::disable_2fa(user_id) {
                        Ok(_) => {},
                        Err(err) => {
                            error!("Error disabling 2FA: {}", err);
                            process::exit(1);
                        }
                    }
                }
                UserCommands::GenBackupCodes {} => {
                    // Mock user ID (in a real app, this would be obtained from the authenticated session)
                    let user_id = "test-user";
                    
                    match cli::user::generate_backup_codes(user_id) {
                        Ok(_) => {},
                        Err(err) => {
                            error!("Error generating backup codes: {}", err);
                            process::exit(1);
                        }
                    }
                }
                UserCommands::Verify2FA { operation, code } => {
                    let user_id = auth.user_id.clone();
                    
                    match cli::user::verify_for_operation(&user_id, &operation, &code) {
                        Ok(()) => {
                            println!("✅ 2FA verification successful for operation: {}", operation);
                        },
                        Err(err) => {
                            error!("Error verifying 2FA: {}", err);
                            std::process::exit(1);
                        }
                    }
                }
                UserCommands::ListUsers {} => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::roles::list_users(&auth) {
                                        println!("Error listing users: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to list users.");
                            process::exit(1);
                        }
                    }
                },
                UserCommands::ChangeRole { user_id, role } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::roles::change_user_role(&auth, &user_id, &role) {
                                        println!("Error changing user role: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to change user roles.");
                            process::exit(1);
                        }
                    }
                },
                UserCommands::ListPermissions {} => {
                    if let Err(e) = cli::roles::list_permissions() {
                        println!("Error listing permissions: {}", e);
                    }
                },
                UserCommands::CheckPermission { permission } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::roles::check_permission(&auth, &permission) {
                                        println!("Error checking permission: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to check permissions.");
                            process::exit(1);
                        }
                    }
                }
            }
        }
        Commands::Account { command } => {
            match command {
                AccountCommands::Create { r#type } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::create_new_account(&auth, r#type) {
                                        println!("Error creating account: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to create an account.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Deposit { id, amount, details } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    // Using the process_transaction function from account module
                                    match crate::account::process_transaction(
                                        &conn, 
                                        &auth, 
                                        id, 
                                        crate::database::models::TransactionType::Deposit, 
                                        *amount,
                                        details
                                    ) {
                                        Ok(transaction) => {
                                            println!("✅ Deposit successful!");
                                            println!("Transaction ID: {}", transaction.id);
                                            println!("Amount: ${:.2}", transaction.amount);
                                            println!("New balance: ${:.2}", 
                                                match crate::account::get_account(&conn, &auth, id) {
                                                    Ok(account) => account.balance,
                                                    Err(_) => 0.0, // Shouldn't happen
                                                }
                                            );
                                        },
                                        Err(e) => {
                                            println!("Error processing deposit: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to make a deposit.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Withdraw { id, amount, details } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    // Using the process_transaction function from account module
                                    match crate::account::process_transaction(
                                        &conn, 
                                        &auth, 
                                        id, 
                                        crate::database::models::TransactionType::Withdrawal, 
                                        *amount,
                                        details
                                    ) {
                                        Ok(transaction) => {
                                            println!("✅ Withdrawal successful!");
                                            println!("Transaction ID: {}", transaction.id);
                                            println!("Amount: ${:.2}", transaction.amount);
                                            println!("New balance: ${:.2}", 
                                                match crate::account::get_account(&conn, &auth, id) {
                                                    Ok(account) => account.balance,
                                                    Err(_) => 0.0, // Shouldn't happen
                                                }
                                            );
                                        },
                                        Err(e) => {
                                            println!("Error processing withdrawal: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to make a withdrawal.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Transfer { from, to, amount, details } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    // Using the transfer_funds function from account module
                                    match crate::account::transfer_funds(
                                        &conn, 
                                        &auth, 
                                        from, 
                                        to, 
                                        *amount,
                                        details
                                    ) {
                                        Ok(transaction) => {
                                            println!("✅ Transfer successful!");
                                            println!("Transaction ID: {}", transaction.id);
                                            println!("Amount: ${:.2}", transaction.amount);
                                            println!("From account: {}", from);
                                            println!("To account: {}", to);
                                        },
                                        Err(e) => {
                                            println!("Error processing transfer: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to make a transfer.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Balance { id } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::get_account_details(&auth, id) {
                                        println!("Error getting account balance: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to view account balance.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::History { id, limit, offset, start_date, end_date } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth_result) => {
                                    if let Err(e) = cli::account::display_transaction_history(
                                        &auth_result, 
                                        &id, 
                                        limit, 
                                        offset, 
                                        start_date.as_deref(), 
                                        end_date.as_deref()
                                    ) {
                                        println!("Error viewing transaction history: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to view transaction history.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Receipt { id } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth_result) => {
                                    if let Err(e) = cli::account::get_transaction_receipt(&auth_result, &id) {
                                        println!("Error retrieving transaction receipt: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to view transaction receipts.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Schedule { id, r#type, amount, date, to, details } => {
                    println!("Scheduling transaction: {} {} {} {} {} {}", id, r#type, amount, date, to.as_deref().unwrap_or("None"), details.as_deref().unwrap_or("None"));
                    // TODO: Implement transaction scheduling
                },
                AccountCommands::Recurring { id, r#type, amount, frequency, start_date, end_date, to, details } => {
                    println!("Creating recurring transaction: {} {} {} {} {} {} {} {}", id, r#type, amount, frequency, start_date, end_date.as_deref().unwrap_or("None"), to.as_deref().unwrap_or("None"), details.as_deref().unwrap_or("None"));
                    // TODO: Implement recurring transaction creation
                },
                AccountCommands::CancelScheduled { id } => {
                    println!("Canceling scheduled transaction: {}", id);
                    // TODO: Implement scheduled transaction cancellation
                },
                AccountCommands::CancelRecurring { id } => {
                    println!("Canceling recurring transaction: {}", id);
                    // TODO: Implement recurring transaction cancellation
                },
                AccountCommands::ProcessScheduled {} => {
                    println!("Running scheduler to process pending scheduled transactions");
                    // TODO: Implement scheduled transaction processing
                },
                AccountCommands::List { user_id } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::list_accounts(&auth, user_id) {
                                        println!("Error listing accounts: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to list accounts.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Status { id, status } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::update_status(&auth, &id, &status) {
                                        println!("Error updating account status: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to update account status.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Interest { id } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::calc_interest(&auth, &id) {
                                        println!("Error calculating interest: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to calculate interest.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Link { primary, accounts } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth) => {
                                    if let Err(e) = cli::account::link_user_accounts(&auth, &primary, &accounts) {
                                        println!("Error linking accounts: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to link accounts.");
                            process::exit(1);
                        }
                    }
                },
                AccountCommands::Export { id, output, format, start_date, end_date, limit } => {
                    match get_auth_token() {
                        Some(token) => {
                            let conn = database::get_connection().unwrap_or_else(|e| {
                                error!("Failed to connect to the database: {}", e);
                                process::exit(1);
                            });
                            
                            match security::authenticate(&conn, &token) {
                                Ok(auth_result) => {
                                    if let Err(e) = cli::account::export_transaction_history(
                                        &auth_result, 
                                        &id, 
                                        &format, 
                                        &output, 
                                        start_date.as_deref(), 
                                        end_date.as_deref(),
                                        limit
                                    ) {
                                        println!("Error exporting transaction history: {}", e);
                                    }
                                },
                                Err(e) => {
                                    println!("Authentication error: {}", e);
                                    process::exit(1);
                                }
                            }
                        },
                        None => {
                            println!("You must be logged in to export transaction history.");
                            process::exit(1);
                        }
                    }
                },
            }
        }
        Commands::Security { command } => {
            match command {
                SecurityCommands::ComplianceCheck {} => {
                    println!("Running compliance check");
                    // TODO: Implement compliance check
                }
                SecurityCommands::Backup { output } => {
                    println!("Creating encrypted backup: {}", output);
                    // TODO: Implement backup
                }
                SecurityCommands::Restore { input } => {
                    println!("Restoring from encrypted backup: {}", input);
                    // TODO: Implement restore
                }
            }
        }
        Commands::Audit { command } => {
            match get_auth_token() {
                Some(token) => {
                    let conn = database::get_connection().unwrap_or_else(|e| {
                        error!("Failed to connect to the database: {}", e);
                        process::exit(1);
                    });
                    
                    match security::authenticate(&conn, &token) {
                        Ok(auth) => {
                            // Use the audit command handler
                            let args_matches = cli::utils::convert_to_argmatches();
                            if let Some(audit_matches) = args_matches.subcommand_matches("audit") {
                                if let Err(e) = cli::audit::handle_audit_command(audit_matches, &auth) {
                                    println!("Error handling audit command: {}", e);
                                }
                            } else {
                                println!("Invalid audit command");
                            }
                        },
                        Err(e) => {
                            println!("Authentication error: {}", e);
                            process::exit(1);
                        }
                    }
                },
                None => {
                    println!("You must be logged in to use audit commands.");
                    process::exit(1);
                }
            }
        }
    }
    
    info!("Shutting down Secure Banking CLI");
} 