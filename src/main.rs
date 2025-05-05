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
    BackupCodes {},
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
    },
    
    /// Withdraw funds
    Withdraw {
        /// Account ID
        #[clap(long)]
        id: String,
        
        /// Amount to withdraw
        #[clap(short, long)]
        amount: f64,
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
                Ok(_) => {},
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
                UserCommands::BackupCodes {} => {
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
            }
        }
        Commands::Account { command } => {
            match command {
                AccountCommands::Create { r#type } => {
                    println!("Creating new account of type: {}", r#type);
                    // TODO: Implement account creation
                }
                AccountCommands::Deposit { id, amount } => {
                    println!("Depositing ${:.2} into account: {}", amount, id);
                    // TODO: Implement deposit
                }
                AccountCommands::Withdraw { id, amount } => {
                    println!("Withdrawing ${:.2} from account: {}", amount, id);
                    // TODO: Implement withdrawal
                }
                AccountCommands::Transfer { from, to, amount } => {
                    println!("Transferring ${:.2} from account: {} to account: {}", amount, from, to);
                    // TODO: Implement transfer
                }
                AccountCommands::Balance { id } => {
                    println!("Getting balance for account: {}", id);
                    // TODO: Implement balance check
                }
                AccountCommands::History { id, limit } => {
                    println!("Getting transaction history for account: {} (limit: {})", id, limit);
                    // TODO: Implement history view
                }
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
    }
    
    info!("Shutting down Secure Banking CLI");
} 