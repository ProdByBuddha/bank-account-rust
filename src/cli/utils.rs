use anyhow::{Result, Context};
use qrcode::{QrCode, render::unicode};
use std::io::{self, Write};
use std::time::Duration;
use std::thread;

/// Display a QR code in the terminal
pub fn display_qr_code(uri: &str) -> Result<()> {
    // Create a QR code from the URI
    let code = QrCode::new(uri).context("Failed to create QR code")?;
    
    // Render the QR code to the terminal
    let qr = code.render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    
    // Print the QR code
    println!("\nScan this QR code with your authenticator app:\n");
    println!("{}", qr);
    println!();
    
    Ok(())
}

/// Display a message with a spinning indicator for ongoing operations
pub fn display_spinner(message: &str, duration: Duration) -> Result<()> {
    let spinner_chars = vec!['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut stdout = io::stdout();
    
    for i in 0..((duration.as_millis() / 100) as usize) {
        let spinner_char = spinner_chars[i % spinner_chars.len()];
        print!("\r{} {} ", spinner_char, message);
        stdout.flush()?;
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("\r✓ {} ", message);
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
    // For cross-platform password reading, we'd use a crate like 'rpassword'
    // But for simplicity in this example, we'll just use a regular read_line
    
    // In a real implementation, replace this with:
    // let password = rpassword::read_password_from_tty(Some(prompt))?;
    
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // Trim whitespace and newlines
    Ok(input.trim().to_string())
}

/// Display recovery codes to the user
pub fn display_recovery_codes(codes: &[String]) -> Result<()> {
    println!("\nYour recovery codes:");
    println!("IMPORTANT: Store these codes in a safe place. They will be used to recover your account if you lose access to your authenticator app.\n");
    
    for (i, code) in codes.iter().enumerate() {
        println!("{:2}. {}", i + 1, code);
    }
    
    println!("\nPlease save these codes immediately. They won't be shown again!\n");
    
    // Ask for confirmation
    let confirmation = read_line("Press Enter when you have saved these codes...")?;
    
    Ok(())
} 