use anyhow::{Result, Context, anyhow};
use qrcode::{QrCode, render::unicode};
use std::io::{self, Write, stdout, stdin};
use std::time::Duration;
use std::thread;

// Color constants for terminal output
const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";

// Progress indicator characters
const SPINNER_CHARS: [char; 4] = ['⠋', '⠙', '⠹', '⠸'];

/// Display a QR code in the terminal
pub fn display_qr_code(uri: &str) -> Result<()> {
    // Create a QR code from the URI
    let code = QrCode::new(uri).context("Failed to create QR code")?;
    
    // Render the QR code to ASCII
    let qr_string = code.render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    
    // Print the QR code
    println!("\nScan this QR code with your authenticator app:\n");
    println!("{}", qr_string);
    println!();
    
    Ok(())
}

/// Display a message with a spinning indicator for ongoing operations
pub fn display_spinner(message: &str, duration: Duration) -> Result<()> {
    print!("{} ", message);
    io::stdout().flush()?;
    
    let start_time = std::time::Instant::now();
    
    while start_time.elapsed() < duration {
        for c in SPINNER_CHARS.iter() {
            print!("\r{} {}", message, c);
            io::stdout().flush()?;
            thread::sleep(Duration::from_millis(100));
            
            if start_time.elapsed() >= duration {
                break;
            }
        }
    }
    
    println!("\r{} ✓", message);
    
    Ok(())
}

/// Read a line of input from the terminal
pub fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // Trim whitespace and newlines
    Ok(input.trim().to_string())
}

/// Read a hidden line of input from the terminal (like a password)
pub fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let password = rpassword::read_password()?;
    
    Ok(password)
}

/// Display recovery codes to the user
pub fn display_recovery_codes(codes: &[String]) -> Result<()> {
    println!("\n===== BACKUP RECOVERY CODES =====");
    println!("⚠️  Keep these codes in a safe place. They can be used to access your account if you lose your authentication device.");
    println!("⚠️  Each code can only be used once.\n");
    
    for code in codes {
        println!("  * {}", code);
    }
    
    println!("\n================================");
    println!("Press Enter to continue...");
    
    // Wait for the user to press Enter
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    
    Ok(())
}

/// Convert clap app to ArgMatches for command handling
pub fn convert_to_argmatches() -> clap::ArgMatches {
    use clap::{Arg, Command};
    
    // Create a command structure similar to what's in main.rs
    let app = Command::new("secure-bank-cli")
        .about("A security-focused terminal-based banking system");
    
    // Add the audit subcommand
    let app = crate::cli::audit::add_audit_commands(app);
    
    // Parse the command line arguments
    app.get_matches()
}

/// Print a success message in green
pub fn print_success(message: &str) {
    println!("{}{}✅ {}{}", GREEN, BOLD, message, RESET);
}

/// Print an error message in red
pub fn print_error(message: &str) {
    println!("{}{}❌ {}{}", RED, BOLD, message, RESET);
}

/// Print a warning message in yellow
pub fn print_warning(message: &str) {
    println!("{}{}⚠️  {}{}", YELLOW, BOLD, message, RESET);
}

/// Print an info message in blue
pub fn print_info(message: &str) {
    println!("{}{}{}{}", BLUE, BOLD, message, RESET);
}

/// Print a header in cyan
pub fn print_header(message: &str) {
    println!("\n{}{}{}{}", CYAN, BOLD, message, RESET);
    println!("{}{}{}", CYAN, "=".repeat(message.len()), RESET);
}

/// Print a section title in magenta
pub fn print_section(message: &str) {
    println!("\n{}{}{}{}", MAGENTA, BOLD, message, RESET);
    println!("{}{}{}", MAGENTA, "-".repeat(message.len()), RESET);
}

/// Interactive input for complex operations
pub struct Interactive;

impl Interactive {
    /// Run an interactive wizard for complex operations
    pub fn wizard<T, F>(title: &str, steps: Vec<&str>, handler: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        print_header(title);
        
        println!("This wizard will guide you through the following steps:");
        for (i, step) in steps.iter().enumerate() {
            println!("  {}{}{}: {}", BOLD, i + 1, RESET, step);
        }
        println!();
        
        let confirm = read_line("Press Enter to continue or type 'q' to quit: ")?;
        if confirm.to_lowercase() == "q" {
            return Err(anyhow!("Operation cancelled by user"));
        }
        
        handler()
    }
    
    /// Get a confirmed input from the user
    pub fn get_confirmed_input(prompt: &str, confirm_prompt: &str, error_message: &str) -> Result<String> {
        let input = read_line(prompt)?;
        let confirm = read_line(confirm_prompt)?;
        
        if input != confirm {
            print_error(error_message);
            return Err(anyhow!(error_message));
        }
        
        Ok(input)
    }
    
    /// Present a menu of choices and get a selection
    pub fn menu<T: Clone>(title: &str, options: &[(String, T)]) -> Result<T> {
        print_section(title);
        
        for (i, (option, _)) in options.iter().enumerate() {
            println!("  {}{}{}: {}", BOLD, i + 1, RESET, option);
        }
        
        loop {
            let input = read_line("\nEnter your choice (number): ")?;
            
            match input.parse::<usize>() {
                Ok(choice) if choice > 0 && choice <= options.len() => {
                    return Ok(options[choice - 1].1.clone());
                }
                _ => {
                    print_error(&format!("Invalid choice. Please enter a number between 1 and {}", options.len()));
                }
            }
        }
    }
    
    /// Display a progress bar
    pub fn progress_bar(message: &str, total_steps: usize) -> ProgressBar {
        ProgressBar::new(message, total_steps)
    }
}

/// A simple progress bar for terminal output
pub struct ProgressBar {
    message: String,
    total: usize,
    current: usize,
}

impl ProgressBar {
    /// Create a new progress bar
    pub fn new(message: &str, total: usize) -> Self {
        let pb = Self {
            message: message.to_string(),
            total,
            current: 0,
        };
        pb.render();
        pb
    }
    
    /// Increment progress
    pub fn increment(&mut self) -> Result<()> {
        self.current = std::cmp::min(self.current + 1, self.total);
        self.render();
        Ok(())
    }
    
    /// Set progress to a specific value
    pub fn set(&mut self, progress: usize) -> Result<()> {
        self.current = std::cmp::min(progress, self.total);
        self.render();
        Ok(())
    }
    
    /// Render the progress bar
    fn render(&self) {
        let width = 30;
        let progress = width * self.current / self.total;
        let bar = "█".repeat(progress) + &"░".repeat(width - progress);
        let percentage = 100 * self.current / self.total;
        
        print!("\r{}: [{}] {}% ({}/{})", 
            self.message, bar, percentage, self.current, self.total);
        io::stdout().flush().unwrap();
        
        if self.current == self.total {
            println!();
        }
    }
    
    /// Mark as completed
    pub fn complete(mut self) -> Result<()> {
        self.set(self.total)?;
        Ok(())
    }
} 