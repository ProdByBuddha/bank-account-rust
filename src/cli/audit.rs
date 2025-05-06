use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use clap::{Arg, ArgMatches, Command};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::Path;
use std::io;

use crate::audit::{AuditLogger, LogArchiver};
use crate::audit::repository::AuditRepository;
use crate::config;
use crate::database::models::AuditEventType;
use crate::security::auth::AuthResult;
use crate::database::get_connection;

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

/// Run a compliance check for security and regulatory requirements
pub fn run_compliance_check(auth: &AuthResult) -> Result<()> {
    // Check admin or security_audit permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"security_audit".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or security auditors can run compliance checks"));
    }
    
    println!("Running security and compliance checks...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Run the compliance check
    let report = audit::compliance::run_compliance_check(&conn)?;
    
    // Print the report
    println!("\n{}", "-".repeat(60));
    println!("SECURITY AND COMPLIANCE REPORT");
    println!("{}", "-".repeat(60));
    
    println!("Total checks run: {}", report.total_checks);
    println!("Passing: {} ({:.1}%)", report.passing_checks, 
             (report.passing_checks as f64 / report.total_checks as f64) * 100.0);
    println!("Warnings: {}", report.warning_checks);
    println!("Failures: {}", report.failing_checks);
    println!("{}", "-".repeat(60));
    
    // Print failures first
    if report.failing_checks > 0 {
        println!("\n❌ CRITICAL ISSUES:");
        for issue in &report.issues {
            if issue.severity == audit::compliance::Severity::Critical {
                println!("- {}: {}", issue.code, issue.message);
                if let Some(remediation) = &issue.remediation {
                    println!("  Remediation: {}", remediation);
                }
            }
        }
    }
    
    // Print warnings
    if report.warning_checks > 0 {
        println!("\n⚠️ WARNINGS:");
        for issue in &report.issues {
            if issue.severity == audit::compliance::Severity::Warning {
                println!("- {}: {}", issue.code, issue.message);
                if let Some(remediation) = &issue.remediation {
                    println!("  Remediation: {}", remediation);
                }
            }
        }
    }
    
    // Print passing checks
    println!("\n✅ PASSING CHECKS:");
    for check in &report.passing {
        println!("- {}: {}", check.code, check.name);
    }
    
    println!("\nCompliance summary: {} of required checks passed", 
            if report.failing_checks == 0 { "All" } else { "Some" });
    
    Ok(())
}

/// Create an encrypted backup of the database
pub fn create_backup(auth: &AuthResult, output_path: &str) -> Result<()> {
    // Check admin or backup_manager permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"backup_manager".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or backup managers can create backups"));
    }
    
    println!("Creating encrypted backup...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Create the backup
    match audit::backup::create_encrypted_backup(&conn, auth, output_path) {
        Ok(metadata) => {
            println!("\n✅ Backup created successfully!");
            println!("Output file: {}", output_path);
            println!("Backup ID: {}", metadata.id);
            println!("Created at: {}", metadata.created_at);
            println!("Database version: {}", metadata.db_version);
            println!("Backup size: {} bytes", metadata.size_bytes);
            println!("\nThis backup is encrypted and can only be restored with proper authentication.");
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to create backup: {}", e)),
    }
}

/// Restore from an encrypted backup
pub fn restore_from_backup(auth: &AuthResult, input_path: &str) -> Result<()> {
    // Check admin permission (only admins should restore)
    if !auth.permissions.contains(&"admin".to_string()) {
        return Err(anyhow!("Permission denied: Only administrators can restore backups"));
    }
    
    // Check if file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow!("Backup file not found: {}", input_path));
    }
    
    // Safety confirmation
    println!("⚠️  WARNING: Restoring from backup will overwrite the current database state.");
    println!("All data changes since the backup was created will be lost.");
    println!("Are you absolutely sure you want to proceed?");
    
    print!("Type 'CONFIRM RESTORE' to continue: ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim() != "CONFIRM RESTORE" {
        println!("Restore operation cancelled.");
        return Ok(());
    }
    
    println!("Restoring from backup...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Restore the backup
    match audit::backup::restore_from_backup(&conn, auth, input_path) {
        Ok(metadata) => {
            println!("\n✅ Backup restored successfully!");
            println!("Backup ID: {}", metadata.id);
            println!("Created at: {}", metadata.created_at);
            println!("Database version: {}", metadata.db_version);
            println!("System has been restored to the state as of {}", metadata.created_at);
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to restore from backup: {}", e)),
    }
}

/// Search audit logs with various filters
pub fn search_audit_logs(
    auth: &AuthResult,
    user_id: Option<&str>,
    account_id: Option<&str>,
    event_type: Option<&str>,
    from_date: Option<&str>,
    to_date: Option<&str>,
    limit: usize,
    text_search: Option<&str>
) -> Result<()> {
    // Check if user has permission to view audit logs
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"view_audit_logs".to_string()) {
        return Err(anyhow!("Permission denied: You don't have permission to view audit logs"));
    }
    
    // Get database connection
    let conn = get_connection()?;
    
    // Parse dates if provided
    let from_datetime = if let Some(date_str) = from_date {
        Some(parse_date_with_default_time(date_str, 0, 0, 0)?)
    } else {
        None
    };
    
    let to_datetime = if let Some(date_str) = to_date {
        Some(parse_date_with_default_time(date_str, 23, 59, 59)?)
    } else {
        None
    };
    
    // Search audit logs
    let logs = audit::search_audit_logs(
        &conn,
        user_id,
        account_id,
        event_type,
        from_datetime.as_ref(),
        to_datetime.as_ref(),
        limit,
        text_search
    )?;
    
    // Display results
    if logs.is_empty() {
        println!("No audit logs found matching the search criteria.");
        return Ok(());
    }
    
    println!("Found {} audit log entries:", logs.len());
    println!("{:<36} {:<20} {:<15} {:<20} {:<20}", "ID", "TIMESTAMP", "EVENT TYPE", "USER ID", "ACCOUNT ID");
    println!("{}", "-".repeat(115));
    
    for log in &logs {
        println!("{:<36} {:<20} {:<15} {:<20} {:<20}",
            log.id,
            log.timestamp.format("%Y-%m-%d %H:%M:%S"),
            log.event_type,
            log.user_id.as_deref().unwrap_or("-"),
            log.account_id.as_deref().unwrap_or("-")
        );
    }
    
    // Ask if user wants to see details for a specific log
    println!("\nTo view details for a specific log entry, enter its ID (or press Enter to skip):");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if !input.is_empty() {
        // Find the log with the given ID
        if let Some(log) = logs.iter().find(|l| l.id == input) {
            println!("\nLog Details:");
            println!("ID: {}", log.id);
            println!("Timestamp: {}", log.timestamp.format("%Y-%m-%d %H:%M:%S"));
            println!("Event Type: {}", log.event_type);
            if let Some(user_id) = &log.user_id {
                println!("User ID: {}", user_id);
            }
            if let Some(account_id) = &log.account_id {
                println!("Account ID: {}", account_id);
            }
            println!("IP Address: {}", log.ip_address.as_deref().unwrap_or("-"));
            println!("Details: {}", log.details);
            println!("Encrypted: {}", if log.is_encrypted { "Yes" } else { "No" });
        } else {
            println!("Log entry with ID '{}' not found.", input);
        }
    }
    
    Ok(())
}

/// Parse a date string with default time components
fn parse_date_with_default_time(
    date_str: &str,
    hour: u32,
    min: u32,
    sec: u32
) -> Result<chrono::DateTime<chrono::Utc>> {
    match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        Ok(date) => {
            let naive_dt = date.and_hms_opt(hour, min, sec)
                .ok_or_else(|| anyhow!("Invalid time components"))?;
            Ok(chrono::DateTime::from_naive_utc_and_offset(naive_dt, chrono::Utc))
        },
        Err(_) => Err(anyhow!("Invalid date format. Please use YYYY-MM-DD format.")),
    }
}

/// Rotate audit logs
pub fn rotate_audit_logs(auth: &AuthResult) -> Result<()> {
    // Check admin or audit_manager permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"audit_manager".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or audit managers can rotate logs"));
    }
    
    println!("Rotating audit logs...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Rotate logs
    match audit::rotate_logs(&conn) {
        Ok(stats) => {
            println!("✅ Audit logs rotated successfully!");
            println!("Archives created: {}", stats.archives_created);
            println!("Logs processed: {}", stats.logs_processed);
            println!("Compression ratio: {:.1}%", stats.compression_ratio * 100.0);
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to rotate audit logs: {}", e)),
    }
}

/// Purge old audit logs based on retention policy
pub fn purge_old_audit_logs(auth: &AuthResult, confirm: bool) -> Result<()> {
    // Check admin permission (only admins should purge logs)
    if !auth.permissions.contains(&"admin".to_string()) {
        return Err(anyhow!("Permission denied: Only administrators can purge audit logs"));
    }
    
    // Get retention policy
    let conn = get_connection()?;
    let retention_days = audit::get_retention_policy(&conn)?;
    
    println!("Current retention policy: {} days", retention_days);
    println!("Logs older than this will be permanently deleted.");
    
    // Ask for confirmation unless --confirm flag was used
    if !confirm {
        println!("⚠️  WARNING: This operation will permanently delete old audit logs.");
        println!("This action cannot be undone.");
        
        print!("Type 'CONFIRM PURGE' to continue: ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if input.trim() != "CONFIRM PURGE" {
            println!("Purge operation cancelled.");
            return Ok(());
        }
    }
    
    // Purge old logs
    match audit::purge_old_logs(&conn) {
        Ok(count) => {
            println!("✅ Successfully purged {} old audit log entries.", count);
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to purge old audit logs: {}", e)),
    }
}

/// Encrypt sensitive information in audit logs
pub fn encrypt_sensitive_audit_data(auth: &AuthResult) -> Result<()> {
    // Check admin or security_admin permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"security_admin".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or security admins can encrypt audit data"));
    }
    
    println!("Encrypting sensitive information in audit logs...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Encrypt sensitive data
    match audit::encrypt_sensitive_data(&conn) {
        Ok(count) => {
            println!("✅ Successfully encrypted sensitive information in {} audit log entries.", count);
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to encrypt sensitive information: {}", e)),
    }
}

/// Export audit logs to a file
pub fn export_audit_logs(
    auth: &AuthResult,
    output_path: &str,
    format: &str,
    user_id: Option<&str>,
    from_date: Option<&str>,
    to_date: Option<&str>
) -> Result<()> {
    // Check admin or audit_export permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"audit_export".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or users with audit_export permission can export logs"));
    }
    
    // Validate format
    let export_format = match format.to_lowercase().as_str() {
        "json" => audit::ExportFormat::Json,
        "csv" => audit::ExportFormat::Csv,
        _ => return Err(anyhow!("Invalid format. Supported formats are 'json' or 'csv'.")),
    };
    
    // Parse dates if provided
    let from_datetime = if let Some(date_str) = from_date {
        Some(parse_date_with_default_time(date_str, 0, 0, 0)?)
    } else {
        None
    };
    
    let to_datetime = if let Some(date_str) = to_date {
        Some(parse_date_with_default_time(date_str, 23, 59, 59)?)
    } else {
        None
    };
    
    println!("Exporting audit logs...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Export logs
    match audit::export_audit_logs(
        &conn,
        output_path,
        export_format,
        user_id,
        from_datetime.as_ref(),
        to_datetime.as_ref()
    ) {
        Ok(count) => {
            println!("✅ Successfully exported {} audit log entries to {}.", count, output_path);
            println!("Format: {}", format);
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to export audit logs: {}", e)),
    }
}

/// Decrypt an encrypted audit log archive
pub fn decrypt_audit_log_archive(auth: &AuthResult, input_path: &str, output_path: &str) -> Result<()> {
    // Check admin permission
    if !auth.permissions.contains(&"admin".to_string()) {
        return Err(anyhow!("Permission denied: Only administrators can decrypt audit log archives"));
    }
    
    // Check if input file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow!("Input file not found: {}", input_path));
    }
    
    println!("Decrypting audit log archive...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Decrypt archive
    match audit::decrypt_log_archive(&conn, auth, input_path, output_path) {
        Ok(metadata) => {
            println!("✅ Successfully decrypted audit log archive to {}.", output_path);
            println!("Archive ID: {}", metadata.id);
            println!("Created at: {}", metadata.created_at);
            println!("Contains {} log entries", metadata.log_count);
            println!("Date range: {} to {}", 
                     metadata.start_date.format("%Y-%m-%d"),
                     metadata.end_date.format("%Y-%m-%d"));
            Ok(())
        },
        Err(e) => Err(anyhow!("Failed to decrypt audit log archive: {}", e)),
    }
}

/// Check for suspicious activity by a user
pub fn check_suspicious_activity(auth: &AuthResult, user_id: &str) -> Result<()> {
    // Check admin or security_admin permission
    if !auth.permissions.contains(&"admin".to_string()) && 
       !auth.permissions.contains(&"security_admin".to_string()) {
        return Err(anyhow!("Permission denied: Only admins or security admins can check for suspicious activity"));
    }
    
    println!("Analyzing user activity for suspicious patterns...");
    
    // Get database connection
    let conn = get_connection()?;
    
    // Check for suspicious activity
    let alerts = audit::analyze_suspicious_activity(&conn, user_id)?;
    
    if alerts.is_empty() {
        println!("✅ No suspicious activity detected for user {}.", user_id);
        return Ok(());
    }
    
    println!("\n⚠️ SUSPICIOUS ACTIVITY ALERTS:");
    println!("{}", "-".repeat(80));
    
    for (i, alert) in alerts.iter().enumerate() {
        println!("Alert #{}: {}", i + 1, alert.title);
        println!("Severity: {}", alert.severity);
        println!("Description: {}", alert.description);
        println!("Timestamp: {}", alert.timestamp.format("%Y-%m-%d %H:%M:%S"));
        println!("Confidence: {:.1}%", alert.confidence * 100.0);
        
        if let Some(related_logs) = &alert.related_logs {
            println!("Related log entries:");
            for log_id in related_logs {
                println!("- {}", log_id);
            }
        }
        
        if i < alerts.len() - 1 {
            println!("{}", "-".repeat(80));
        }
    }
    
    Ok(())
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