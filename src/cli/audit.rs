use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use clap::{Arg, ArgMatches, Command};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::Path;

use crate::audit::{AuditLogger, LogArchiver};
use crate::audit::repository::AuditRepository;
use crate::config;
use crate::database::models::AuditEventType;
use crate::security::auth::AuthResult;

/// Add audit subcommands to the CLI
pub fn add_audit_commands(app: Command) -> Command {
    app.subcommand(
        Command::new("audit")
            .about("Audit trail and logging operations")
            .subcommand(
                Command::new("search")
                    .about("Search audit logs")
                    .arg(
                        Arg::new("user-id")
                            .long("user-id")
                            .short('u')
                            .help("Filter by user ID")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("account-id")
                            .long("account-id")
                            .short('a')
                            .help("Filter by account ID")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("event-type")
                            .long("event-type")
                            .short('e')
                            .help("Filter by event type")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("from-date")
                            .long("from")
                            .help("Start date in YYYY-MM-DD format")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("to-date")
                            .long("to")
                            .help("End date in YYYY-MM-DD format")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("limit")
                            .long("limit")
                            .short('l')
                            .help("Maximum number of records to return")
                            .takes_value(true)
                            .default_value("50"),
                    )
                    .arg(
                        Arg::new("details-search")
                            .long("text")
                            .short('t')
                            .help("Search in log details text")
                            .takes_value(true),
                    ),
            )
            .subcommand(
                Command::new("rotate")
                    .about("Rotate audit logs if they exceed the maximum size"),
            )
            .subcommand(
                Command::new("purge")
                    .about("Purge old audit logs based on retention policy")
                    .arg(
                        Arg::new("confirm")
                            .long("confirm")
                            .help("Confirm purging without additional prompt"),
                    ),
            )
            .subcommand(
                Command::new("encrypt-sensitive")
                    .about("Encrypt sensitive information in audit logs"),
            )
            .subcommand(
                Command::new("export")
                    .about("Export audit logs to a file")
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .help("Output file path")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .short('f')
                            .help("Output format (json or csv)")
                            .takes_value(true)
                            .default_value("json"),
                    )
                    .arg(
                        Arg::new("user-id")
                            .long("user-id")
                            .short('u')
                            .help("Filter by user ID")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("from-date")
                            .long("from")
                            .help("Start date in YYYY-MM-DD format")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("to-date")
                            .long("to")
                            .help("End date in YYYY-MM-DD format")
                            .takes_value(true),
                    ),
            )
            .subcommand(
                Command::new("decrypt")
                    .about("Decrypt an encrypted audit log archive")
                    .arg(
                        Arg::new("input")
                            .long("input")
                            .short('i')
                            .help("Input encrypted file path")
                            .takes_value(true)
                            .required(true),
                    )
                    .arg(
                        Arg::new("output")
                            .long("output")
                            .short('o')
                            .help("Output file path")
                            .takes_value(true)
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("suspicious")
                    .about("Check for suspicious activity")
                    .arg(
                        Arg::new("user-id")
                            .long("user-id")
                            .short('u')
                            .help("User ID to check")
                            .takes_value(true)
                            .required(true),
                    ),
            ),
    )
}

/// Handle audit commands
pub fn handle_audit_command(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    match matches.subcommand() {
        Some(("search", sub_matches)) => search_audit_logs(sub_matches, auth_result),
        Some(("rotate", _)) => rotate_audit_logs(auth_result),
        Some(("purge", sub_matches)) => purge_audit_logs(sub_matches, auth_result),
        Some(("encrypt-sensitive", _)) => encrypt_sensitive_logs(auth_result),
        Some(("export", sub_matches)) => export_audit_logs(sub_matches, auth_result),
        Some(("decrypt", sub_matches)) => decrypt_audit_log(sub_matches, auth_result),
        Some(("suspicious", sub_matches)) => check_suspicious_activity(sub_matches, auth_result),
        _ => {
            println!("Use one of the audit subcommands. Try 'audit --help' for more information.");
            Ok(())
        }
    }
}

/// Search audit logs based on criteria
fn search_audit_logs(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.search".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to search audit logs"));
    }
    
    let user_id = matches.value_of("user-id");
    let account_id = matches.value_of("account-id");
    let event_type_str = matches.value_of("event-type");
    let from_date_str = matches.value_of("from-date");
    let to_date_str = matches.value_of("to-date");
    let limit = matches.value_of("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(50);
    let details_search = matches.value_of("details-search");
    
    let mut filters = HashMap::new();
    
    if let Some(user) = user_id {
        filters.insert("user_id".to_string(), user.to_string());
    }
    
    if let Some(account) = account_id {
        filters.insert("account_id".to_string(), account.to_string());
    }
    
    if let Some(event) = event_type_str {
        match AuditEventType::from_str(event) {
            Ok(event_type) => {
                filters.insert("event_type".to_string(), event_type.as_str().to_string());
            },
            Err(e) => {
                return Err(anyhow::anyhow!("Invalid event type: {}", e));
            }
        }
    }
    
    if let Some(text) = details_search {
        filters.insert("details_search".to_string(), text.to_string());
    }
    
    let from_date = if let Some(date_str) = from_date_str {
        Some(parse_date(date_str)?)
    } else {
        None
    };
    
    let to_date = if let Some(date_str) = to_date_str {
        Some(parse_date(date_str)?)
    } else {
        None
    };
    
    // Search for audit logs
    let audit_logs = AuditRepository::search_audit_logs(
        filters,
        from_date,
        to_date,
        Some(limit),
        None,
    )?;
    
    if audit_logs.is_empty() {
        println!("No audit logs found matching the criteria.");
        return Ok(());
    }
    
    // Display results
    println!("Found {} audit logs:", audit_logs.len());
    println!("{:<36} {:<20} {:<15} {:<24} {}", "ID", "Event Type", "User ID", "Timestamp", "Details");
    println!("{:-<36} {:-<20} {:-<15} {:-<24} {:-<40}", "", "", "", "", "");
    
    for log in audit_logs {
        let user_display = log.user_id.as_deref().unwrap_or("-");
        
        // Format date to local time for better readability
        let local_time = log.timestamp.with_timezone(&Local);
        let formatted_time = local_time.format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Truncate details if too long
        let details = log.details.as_deref().unwrap_or("-");
        let details_display = if details.len() > 40 {
            format!("{}...", &details[0..37])
        } else {
            details.to_string()
        };
        
        println!("{:<36} {:<20} {:<15} {:<24} {}", 
                 log.id, 
                 log.event_type.as_str(), 
                 user_display,
                 formatted_time,
                 details_display);
    }
    
    Ok(())
}

/// Rotate audit logs if needed
fn rotate_audit_logs(auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.admin".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to rotate audit logs"));
    }
    
    let logger = AuditLogger::new()?;
    logger.check_log_rotation()?;
    
    println!("Audit log rotation check completed successfully.");
    Ok(())
}

/// Purge old audit logs based on retention policy
fn purge_audit_logs(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.admin".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to purge audit logs"));
    }
    
    let confirmed = matches.is_present("confirm");
    
    if !confirmed {
        println!("WARNING: This will permanently delete old audit logs based on retention policy.");
        println!("Are you sure you want to continue? [y/N]");
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Operation cancelled.");
            return Ok(());
        }
    }
    
    let logger = AuditLogger::new()?;
    let purged_count = logger.clean_old_logs()?;
    
    println!("Purged {} old audit logs.", purged_count);
    Ok(())
}

/// Encrypt sensitive information in audit logs
fn encrypt_sensitive_logs(auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.admin".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to encrypt audit logs"));
    }
    
    let logger = AuditLogger::new()?;
    let encrypted_count = logger.encrypt_sensitive_logs()?;
    
    println!("Encrypted sensitive information in {} audit logs.", encrypted_count);
    Ok(())
}

/// Export audit logs to a file
fn export_audit_logs(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.export".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to export audit logs"));
    }
    
    let output_path = matches.value_of("output").unwrap(); // Required arg
    let format = matches.value_of("format").unwrap_or("json");
    
    let user_id = matches.value_of("user-id");
    let from_date_str = matches.value_of("from-date");
    let to_date_str = matches.value_of("to-date");
    
    let mut filters = HashMap::new();
    
    if let Some(user) = user_id {
        filters.insert("user_id".to_string(), user.to_string());
    }
    
    let from_date = if let Some(date_str) = from_date_str {
        Some(parse_date(date_str)?)
    } else {
        None
    };
    
    let to_date = if let Some(date_str) = to_date_str {
        Some(parse_date(date_str)?)
    } else {
        None
    };
    
    // Get the audit logs
    let audit_logs = AuditRepository::search_audit_logs(
        filters,
        from_date,
        to_date,
        None, // No limit for export
        None,
    )?;
    
    if audit_logs.is_empty() {
        println!("No audit logs found matching the criteria.");
        return Ok(());
    }
    
    // Export based on format
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&audit_logs)?;
            std::fs::write(output_path, json)?;
        },
        "csv" => {
            let mut file = std::fs::File::create(output_path)?;
            // Write CSV header
            writeln!(file, "ID,EventType,UserID,AccountID,TransactionID,IPAddress,Timestamp,Details")?;
            
            // Write each log as a CSV row
            for log in audit_logs {
                writeln!(
                    file,
                    "{},{},{},{},{},{},{},\"{}\"",
                    log.id,
                    log.event_type.as_str(),
                    log.user_id.unwrap_or_default(),
                    log.account_id.unwrap_or_default(),
                    log.transaction_id.unwrap_or_default(),
                    log.ip_address.unwrap_or_default(),
                    log.timestamp.to_rfc3339(),
                    log.details.unwrap_or_default().replace("\"", "\"\""), // Escape quotes for CSV
                )?;
            }
        },
        _ => {
            return Err(anyhow::anyhow!("Unsupported export format: {}", format));
        }
    }
    
    println!("Exported {} audit logs to {}", audit_logs.len(), output_path);
    Ok(())
}

/// Decrypt an encrypted audit log archive
fn decrypt_audit_log(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.admin".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to decrypt audit logs"));
    }
    
    let input_path = matches.value_of("input").unwrap(); // Required arg
    let output_path = matches.value_of("output").unwrap(); // Required arg
    
    // Create archiver
    let archiver = LogArchiver::new()?;
    
    // Check if input file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!("Input file does not exist: {}", input_path));
    }
    
    // Decrypt the file
    let decrypted_path = archiver.decrypt_archive(Path::new(input_path), Some(Path::new(output_path)))?;
    
    println!("Successfully decrypted log archive to {}", decrypted_path.display());
    Ok(())
}

/// Check for suspicious activity
fn check_suspicious_activity(matches: &ArgMatches, auth_result: &AuthResult) -> Result<()> {
    // Check authorization
    if !auth_result.permissions.contains(&"audit.search".to_string()) {
        return Err(anyhow::anyhow!("You don't have permission to search audit logs"));
    }
    
    let user_id = matches.value_of("user-id").unwrap(); // Required arg
    
    // Create logger
    let logger = AuditLogger::new()?;
    
    // Check for suspicious activity
    let suspicious_logs = logger.check_suspicious_activity(user_id)?;
    
    if suspicious_logs.is_empty() {
        println!("No suspicious activity detected for user {}.", user_id);
        return Ok(());
    }
    
    // Display results
    println!("Found {} suspicious events for user {}:", suspicious_logs.len(), user_id);
    println!("{:<20} {:<24} {}", "Event Type", "Timestamp", "Details");
    println!("{:-<20} {:-<24} {:-<40}", "", "", "");
    
    for log in suspicious_logs {
        // Format date to local time for better readability
        let local_time = log.timestamp.with_timezone(&Local);
        let formatted_time = local_time.format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Truncate details if too long
        let details = log.details.as_deref().unwrap_or("-");
        let details_display = if details.len() > 60 {
            format!("{}...", &details[0..57])
        } else {
            details.to_string()
        };
        
        println!("{:<20} {:<24} {}", 
                 log.event_type.as_str(), 
                 formatted_time,
                 details_display);
    }
    
    Ok(())
}

/// Parse a date string in YYYY-MM-DD format to DateTime<Utc>
fn parse_date(date_str: &str) -> Result<DateTime<Utc>> {
    // Parse the date string
    let naive_date = NaiveDateTime::parse_from_str(&format!("{} 00:00:00", date_str), "%Y-%m-%d %H:%M:%S")
        .context(format!("Invalid date format: {}. Expected YYYY-MM-DD.", date_str))?;
    
    // Convert to UTC
    Ok(DateTime::<Utc>::from_utc(naive_date, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_date() {
        let date = parse_date("2023-04-15").unwrap();
        assert_eq!(date.year(), 2023);
        assert_eq!(date.month(), 4);
        assert_eq!(date.day(), 15);
        assert_eq!(date.hour(), 0);
        assert_eq!(date.minute(), 0);
        
        // Test invalid format
        let result = parse_date("invalid");
        assert!(result.is_err());
    }
} 