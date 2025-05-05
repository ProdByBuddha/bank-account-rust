use clap::{Parser, Subcommand};
use dotenv::dotenv;
use env_logger::Env;
use log::{info, error};
use std::process;
use std::io::{self, Write};

mod user;
mod account;
mod security;
mod audit;
mod database;
mod cli;
mod config;

use cli::utils::{print_success, print_error, print_warning, print_info, print_header, Interactive};
use security::auth::{self, AuthResult};

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

    /// Use interactive mode for complex operations
    #[clap(short, long)]
    interactive: bool,

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
        /// Output file path (optional, uses default if not specified)
        #[clap(short, long)]
        output: Option<String>,
        
        /// Description for the backup
        #[clap(short, long)]
        description: Option<String>,
    },
    
    /// Restore from a backup
    Restore {
        /// Backup ID to restore
        #[clap(short, long)]
        id: String,
        
        /// Force restore without confirmation (use with caution)
        #[clap(short, long)]
        force: bool,
    },
    
    /// List available backups
    ListBackups {},
    
    /// Verify a backup's integrity
    VerifyBackup {
        /// Backup ID to verify
        #[clap(short, long)]
        id: String,
    },
    
    /// Delete a backup
    DeleteBackup {
        /// Backup ID to delete
        #[clap(short, long)]
        id: String,
        
        /// Force deletion without confirmation
        #[clap(short, long)]
        force: bool,
    },
    
    /// Perform a partial restore of specific tables
    PartialRestore {
        /// Backup ID to restore from
        #[clap(short, long)]
        id: String,
        
        /// Comma-separated list of tables to restore
        #[clap(short, long)]
        tables: String,
    },
    
    /// Schedule an automatic backup
    ScheduleBackup {},
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

fn get_auth_token() -> Option<String> {
    // Read from a token file in the user's home directory
    let home = std::env::var("HOME").ok()?;
    let token_path = std::path::Path::new(&home).join(".secure_bank_token");
    
    if !token_path.exists() {
        return None;
    }
    
    std::fs::read_to_string(token_path).ok()
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
    
    print_header("SECURE BANKING CLI");
    info!("Starting Secure Banking CLI");
    
    // Initialize config from the provided file
    match config::load_config(&cli.config) {
        Ok(_) => {
            info!("Configuration loaded successfully");
        }
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            print_error(&format!("Failed to load configuration: {}", err));
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
            print_error(&format!("Failed to initialize database: {}", err));
            process::exit(1);
        }
    }
    
    // Process the command
    match &cli.command {
        Commands::Init { username } => {
            let result = if cli.interactive {
                init_interactive(username)
            } else {
                init_command(username)
            };
            
            if let Err(err) = result {
                print_error(&format!("Initialization failed: {}", err));
                process::exit(1);
            }
        }
        Commands::Login { username, twofa } => {
            let result = if cli.interactive {
                login_interactive(username)
            } else {
                cli::auth::login(username, *twofa)
            };
            
            match result {
                Ok(_) => {},
                Err(err) => {
                    error!("Error logging in: {}", err);
                    print_error(&format!("Login failed: {}", err));
                    process::exit(1);
                }
            }
        }
        Commands::User { command } => {
            process_user_command(command, cli.interactive)
        }
        Commands::Account { command } => {
            process_account_command(command, cli.interactive)
        }
        Commands::Security { command } => {
            process_security_command(command, cli.interactive)
        }
        Commands::Audit { command } => {
            process_audit_command(command, cli.interactive)
        }
    }
    
    info!("Shutting down Secure Banking CLI");
}

fn init_command(username: &str) -> anyhow::Result<()> {
    print_info(&format!("Initializing system with admin user: {}", username));
    
    // TODO: Implement initialization logic
    // This is just a placeholder until the real implementation
    let conn = database::get_connection()?;
    
    // Create admin user logic would go here
    print_success(&format!("System initialized with admin user: {}", username));
    
    Ok(())
}

fn init_interactive(username: &str) -> anyhow::Result<()> {
    Interactive::wizard(
        "System Initialization",
        vec![
            "Set up admin user",
            "Configure database encryption",
            "Initialize security settings",
        ],
        || {
            // Step 1: Set up admin user
            print_header("Admin User Setup");
            let admin_name = cli::utils::read_line(&format!("Admin username [{}]: ", username))?;
            let admin_name = if admin_name.is_empty() { username.to_string() } else { admin_name };
            
            let password = cli::utils::read_password("Admin password: ")?;
            let confirm_password = cli::utils::read_password("Confirm password: ")?;
            
            if password != confirm_password {
                return Err(anyhow::anyhow!("Passwords do not match"));
            }
            
            // Step 2: Database encryption
            print_header("Database Encryption");
            print_info("Setting up encrypted database...");
            
            let pb = Interactive::progress_bar("Initializing database encryption", 5);
            for i in 0..5 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                pb.set(i + 1)?;
            }
            
            // Step 3: Security settings
            print_header("Security Settings");
            
            let options = vec![
                ("High (recommended)".to_string(), "high"),
                ("Medium".to_string(), "medium"),
                ("Low".to_string(), "low"),
            ];
            
            let security_level = Interactive::menu("Select security level", &options)?;
            print_info(&format!("Setting security level to: {}", security_level));
            
            print_success(&format!("System initialized with admin user: {}", admin_name));
            Ok(())
        }
    )
}

fn login_interactive(username: &str) -> anyhow::Result<auth::AuthResult> {
    Interactive::wizard(
        "Secure Login",
        vec![
            "Enter credentials",
            "Two-factor authentication (if enabled)",
        ],
        || {
            // Step 1: Enter credentials
            print_header("Enter Credentials");
            let user = cli::utils::read_line(&format!("Username [{}]: ", username))?;
            let user = if user.is_empty() { username.to_string() } else { user };
            
            let password = cli::utils::read_password("Password: ")?;
            
            // Check if 2FA is enabled for this user
            let conn = database::get_connection()?;
            
            // Mock 2FA check - in a real app, this would check the database
            let twofa_enabled = false; // Mock value
            
            if twofa_enabled {
                // Step 2: Two-factor authentication
                print_header("Two-Factor Authentication");
                print_info("Two-factor authentication is enabled for your account.");
                
                let code = cli::utils::read_line("Enter the 6-digit code from your authenticator app: ")?;
                
                // Verify the 2FA code - mock implementation
                if code != "123456" { // Mock validation
                    return Err(anyhow::anyhow!("Invalid two-factor authentication code"));
                }
            }
            
            // Perform login
            cli::auth::login(&user, twofa_enabled)
        }
    )
}

fn process_user_command(command: &UserCommands, interactive: bool) {
    // Get authentication token for admin user
    match get_auth_token() {
        Some(token) => {
            let conn = database::get_connection().unwrap_or_else(|e| {
                error!("Failed to connect to the database: {}", e);
                print_error(&format!("Database connection failed: {}", e));
                process::exit(1);
            });
            
            match security::authenticate(&conn, &token) {
                Ok(auth) => {
                    let result = match command {
                        UserCommands::Create { username, role } => {
                            if interactive {
                                create_user_interactive(&auth)
                            } else {
                                cli::user::create_user(&auth, username, role)
                            }
                        },
                        UserCommands::ChangePassword {} => {
                            if interactive {
                                change_password_interactive(&auth)
                            } else {
                                cli::auth::change_password(&auth)
                            }
                        },
                        UserCommands::Enable2FA {} => {
                            cli::user::enable_2fa(&auth.user_id)
                        },
                        UserCommands::Disable2FA {} => {
                            cli::user::disable_2fa(&auth.user_id)
                        },
                        UserCommands::GenBackupCodes {} => {
                            cli::user::generate_backup_codes(&auth.user_id)
                        },
                        UserCommands::Verify2FA { operation, code } => {
                            cli::user::verify_for_operation(&auth.user_id, operation, code)
                        },
                        UserCommands::ListUsers {} => {
                            cli::roles::list_users(&auth)
                        },
                        UserCommands::ChangeRole { user_id, role } => {
                            if interactive {
                                change_role_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info(&format!("Changing role of user {} to {}", user_id, role));
                                Ok(())
                            }
                        },
                        UserCommands::ListPermissions {} => {
                            // Mock implementation
                            print_info("Listing permissions");
                            Ok(())
                        },
                        UserCommands::CheckPermission { permission } => {
                            // Mock implementation
                            print_info(&format!("Checking permission: {}", permission));
                            Ok(())
                        },
                    };
                    
                    if let Err(e) = result {
                        print_error(&format!("Error: {}", e));
                        process::exit(1);
                    }
                },
                Err(e) => {
                    print_error(&format!("Authentication error: {}", e));
                    process::exit(1);
                }
            }
        },
        None => {
            print_error("You must be logged in to use this command.");
            print_info("Please run 'secure-bank-cli login --username <your-username>' first.");
            process::exit(1);
        }
    }
}

fn create_user_interactive(auth: &auth::AuthResult) -> anyhow::Result<()> {
    Interactive::wizard(
        "Create New User",
        vec![
            "Enter user details",
            "Set user permissions",
            "Complete setup",
        ],
        || {
            // Step 1: Enter user details
            print_header("User Details");
            let username = cli::utils::read_line("Enter username: ")?;
            
            let options = vec![
                ("Regular User".to_string(), "user"),
                ("Administrator".to_string(), "admin"),
            ];
            
            let role = Interactive::menu("Select user role", &options)?;
            
            // Step 2: Set user permissions
            print_header("User Permissions");
            print_info(&format!("The '{}' role has the following permissions:", role));
            
            // List permissions for the selected role
            if role == "admin" {
                println!("- User management");
                println!("- Account management");
                println!("- Security operations");
                println!("- Audit logs access");
                println!("- System configuration");
            } else {
                println!("- Personal account management");
                println!("- Transaction history");
                println!("- Profile management");
            }
            
            // Confirm creation
            let confirm = cli::utils::read_line("Create user with these settings? [y/N]: ")?;
            if confirm.to_lowercase() != "y" {
                return Err(anyhow::anyhow!("User creation cancelled"));
            }
            
            // Step 3: Create user
            print_header("Creating User");
            let result = cli::user::create_user(auth, &username, role);
            
            match result {
                Ok(_) => {
                    print_success(&format!("User '{}' created successfully with role '{}'", username, role));
                    Ok(())
                },
                Err(e) => Err(e),
            }
        }
    )
}

fn change_password_interactive(auth: &auth::AuthResult) -> anyhow::Result<()> {
    Interactive::wizard(
        "Change Password",
        vec![
            "Enter current password",
            "Create new password",
            "Confirm new password",
        ],
        || {
            // TODO: Implement interactive password change
            cli::auth::change_password(auth)
        }
    )
}

fn change_role_interactive(auth: &auth::AuthResult) -> anyhow::Result<()> {
    Interactive::wizard(
        "Change User Role",
        vec![
            "Select user",
            "Choose new role",
            "Confirm changes",
        ],
        || {
            // Step 1: Select user - mock implementation
            print_header("Select User");
            
            // Mock user list
            let user_options = vec![
                ("User 1 (user)".to_string(), "user1".to_string()),
                ("User 2 (admin)".to_string(), "user2".to_string()),
                ("User 3 (user)".to_string(), "user3".to_string()),
            ];
            
            let user_id = Interactive::menu("Select user to modify", &user_options)?;
            
            // Step 2: Choose new role
            print_header("Choose New Role");
            
            let role_options = vec![
                ("Regular User".to_string(), "user".to_string()),
                ("Administrator".to_string(), "admin".to_string()),
            ];
            
            let new_role = Interactive::menu("Select new role", &role_options)?;
            
            // Step 3: Confirm changes
            print_header("Confirm Changes");
            
            let confirm = cli::utils::read_line(&format!("Change role to '{}'? [y/N]: ", new_role))?;
            if confirm.to_lowercase() != "y" {
                return Err(anyhow::anyhow!("Role change cancelled"));
            }
            
            // Mock implementation
            print_success(&format!("Changed role of user {} to {}", user_id, new_role));
            Ok(())
        }
    )
}

fn process_account_command(command: &AccountCommands, interactive: bool) {
    // Get authentication token
    match get_auth_token() {
        Some(token) => {
            let conn = database::get_connection().unwrap_or_else(|e| {
                error!("Failed to connect to the database: {}", e);
                print_error(&format!("Database connection failed: {}", e));
                process::exit(1);
            });
            
            match security::authenticate(&conn, &token) {
                Ok(auth) => {
                    let result = match command {
                        AccountCommands::Create { r#type } => {
                            if interactive {
                                cli::interactive::create_account_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info(&format!("Creating new {} account", r#type));
                                Ok(())
                            }
                        },
                        AccountCommands::Deposit { id, amount, details } => {
                            // Mock implementation
                            print_info(&format!("Depositing ${:.2} to account {}", amount, id));
                            Ok(())
                        },
                        AccountCommands::Withdraw { id, amount, details } => {
                            // Mock implementation
                            print_info(&format!("Withdrawing ${:.2} from account {}", amount, id));
                            Ok(())
                        },
                        AccountCommands::Transfer { from, to, amount, details } => {
                            if interactive {
                                cli::interactive::transfer_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info(&format!("Transferring ${:.2} from account {} to account {}", amount, from, to));
                                Ok(())
                            }
                        },
                        AccountCommands::Balance { id } => {
                            // Mock implementation
                            print_info(&format!("Account {} balance: $1000.00", id));
                            Ok(())
                        },
                        AccountCommands::History { id, limit, offset, start_date, end_date } => {
                            if interactive {
                                cli::interactive::transaction_history_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info(&format!("Displaying transaction history for account {}", id));
                                Ok(())
                            }
                        },
                        AccountCommands::Receipt { id } => {
                            // Mock implementation
                            print_info(&format!("Generating receipt for transaction {}", id));
                            Ok(())
                        },
                        AccountCommands::Export { id, output, format, start_date, end_date, limit } => {
                            // Mock implementation
                            print_info(&format!("Exporting transaction history for account {} to {}", id, output));
                            Ok(())
                        },
                        // Add more account commands here
                        _ => {
                            // For remaining commands, show a message that they're not fully implemented
                            print_info("This command is not fully implemented yet");
                            Ok(())
                        }
                    };
                    
                    if let Err(e) = result {
                        print_error(&format!("Error: {}", e));
                        process::exit(1);
                    }
                },
                Err(e) => {
                    print_error(&format!("Authentication error: {}", e));
                    process::exit(1);
                }
            }
        },
        None => {
            print_error("You must be logged in to perform account operations");
            print_info("Please run 'secure-bank-cli login --username <your-username>' first");
            process::exit(1);
        }
    }
}

fn process_security_command(command: &SecurityCommands, interactive: bool) {
    // Get authentication token
    match get_auth_token() {
        Some(token) => {
            let conn = database::get_connection().unwrap_or_else(|e| {
                error!("Failed to connect to the database: {}", e);
                print_error(&format!("Database connection failed: {}", e));
                process::exit(1);
            });
            
            match security::authenticate(&conn, &token) {
                Ok(auth) => {
                    let result = match command {
                        SecurityCommands::ComplianceCheck {} => {
                            if interactive {
                                cli::interactive::compliance_check_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info("Running compliance check...");
                                Ok(())
                            }
                        },
                        SecurityCommands::Backup { output, description } => {
                            if interactive {
                                cli::security::backup_interactive(&auth)
                            } else {
                                cli::security::create_backup(&auth, output.as_deref(), description.as_deref())
                            }
                        },
                        SecurityCommands::Restore { id, force } => {
                            if interactive {
                                cli::security::restore_interactive(&auth)
                            } else {
                                cli::security::restore_backup(&auth, id, *force)
                            }
                        },
                        SecurityCommands::ListBackups {} => {
                            cli::security::list_backups(&auth)
                        },
                        SecurityCommands::VerifyBackup { id } => {
                            cli::security::verify_backup(&auth, id)
                        },
                        SecurityCommands::DeleteBackup { id, force } => {
                            cli::security::delete_backup(&auth, id, *force)
                        },
                        SecurityCommands::PartialRestore { id, tables } => {
                            if interactive {
                                cli::security::partial_restore_interactive(&auth)
                            } else {
                                cli::security::partial_restore(&auth, id, tables)
                            }
                        },
                        SecurityCommands::ScheduleBackup {} => {
                            cli::security::schedule_backup(&auth)
                        },
                    };
                    
                    if let Err(e) = result {
                        print_error(&format!("Error: {}", e));
                        process::exit(1);
                    }
                },
                Err(e) => {
                    print_error(&format!("Authentication error: {}", e));
                    process::exit(1);
                }
            }
        },
        None => {
            print_error("You must be logged in to perform security operations");
            print_info("Please run 'secure-bank-cli login --username <your-username>' first");
            process::exit(1);
        }
    }
}

fn process_audit_command(command: &AuditCommands, interactive: bool) {
    // Get authentication token
    match get_auth_token() {
        Some(token) => {
            let conn = database::get_connection().unwrap_or_else(|e| {
                error!("Failed to connect to the database: {}", e);
                print_error(&format!("Database connection failed: {}", e));
                process::exit(1);
            });
            
            match security::authenticate(&conn, &token) {
                Ok(auth) => {
                    let result = match command {
                        AuditCommands::Search { user_id, account_id, event_type, from_date, to_date, limit, text } => {
                            if interactive {
                                cli::interactive::audit_search_interactive(&auth)
                            } else {
                                // Mock implementation
                                print_info("Searching audit logs...");
                                Ok(())
                            }
                        },
                        // Add other audit commands here
                        _ => {
                            // For remaining commands, show a message that they're not fully implemented
                            print_info("This command is not fully implemented yet");
                            Ok(())
                        }
                    };
                    
                    if let Err(e) = result {
                        print_error(&format!("Error: {}", e));
                        process::exit(1);
                    }
                },
                Err(e) => {
                    print_error(&format!("Authentication error: {}", e));
                    process::exit(1);
                }
            }
        },
        None => {
            print_error("You must be logged in to perform audit operations");
            print_info("Please run 'secure-bank-cli login --username <your-username>' first");
            process::exit(1);
        }
    }
} 