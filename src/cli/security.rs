use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use log::{debug, error, info, warn};
use std::io::{self, Write};
use std::path::Path;

use crate::cli::utils::{print_error, print_info, print_success, print_warning, Interactive};
use crate::database::backup;
use crate::security::auth::AuthResult;

/// Create a backup with optional custom path and description
pub fn create_backup(
    auth: &AuthResult,
    output_path: Option<&str>,
    description: Option<&str>,
) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_create") {
        return Err(anyhow!("You don't have permission to create backups"));
    }

    let desc = description.map(|d| d.to_string());
    
    // Create the backup
    print_info("Creating database backup...");
    let backup_id = backup::create_backup(desc, Some(&auth.user.id))?;
    
    // If custom output path is provided, copy the backup to that location as well
    if let Some(path) = output_path {
        print_info(&format!("Copying backup to custom location: {}", path));
        // Logic to copy the backup file to the custom location would go here
        // For now, we'll just show a message
        print_info("Custom backup location feature is not fully implemented");
    }
    
    print_success(&format!("Backup created successfully with ID: {}", backup_id));
    Ok(())
}

/// Restore a database from a backup
pub fn restore_backup(auth: &AuthResult, backup_id: &str, force: bool) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_restore") {
        return Err(anyhow!("You don't have permission to restore backups"));
    }
    
    // Get backup details
    let backups = backup::list_backups()?;
    let backup_details = backups
        .iter()
        .find(|b| b.id == backup_id)
        .ok_or_else(|| anyhow!("Backup with ID {} not found", backup_id))?;
    
    // Confirm restoration if not forced
    if !force {
        print_warning("You are about to restore the database from a backup.");
        print_warning("This will overwrite the current database. All changes since the backup will be lost.");
        print_info(&format!(
            "Backup details:\n- ID: {}\n- Created: {}\n- Description: {}",
            backup_details.id,
            backup_details.created_at.format("%Y-%m-%d %H:%M:%S"),
            backup_details.description.as_deref().unwrap_or("None")
        ));
        
        print_warning("Are you sure you want to continue? (y/N): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            print_info("Restoration cancelled by user");
            return Ok(());
        }
    }
    
    // Perform the restoration
    print_info(&format!("Restoring database from backup {}...", backup_id));
    backup::restore_backup(backup_id, Some(&auth.user.id))?;
    
    print_success("Database restored successfully");
    Ok(())
}

/// List all available backups
pub fn list_backups(auth: &AuthResult) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_list") {
        return Err(anyhow!("You don't have permission to list backups"));
    }
    
    // Get backups
    let backups = backup::list_backups()?;
    
    if backups.is_empty() {
        print_info("No backups found");
        return Ok(());
    }
    
    // Display backups
    print_info("Available backups:");
    print_info("------------------------------------------------------------");
    print_info("ID        | Created             | Size     | Description    ");
    print_info("------------------------------------------------------------");
    
    for backup in backups {
        let created = backup.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
        let size = format_size(backup.size_bytes);
        let desc = backup.description.as_deref().unwrap_or("No description");
        
        print_info(&format!(
            "{:<9} | {:<19} | {:<8} | {}",
            &backup.id[..8],
            created,
            size,
            if desc.len() > 30 { &desc[..27].to_string() + "..." } else { desc }
        ));
    }
    
    print_info("------------------------------------------------------------");
    print_info(&format!("Total: {} backups", backups.len()));
    
    Ok(())
}

/// Verify a backup's integrity
pub fn verify_backup(auth: &AuthResult, backup_id: &str) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_verify") {
        return Err(anyhow!("You don't have permission to verify backups"));
    }
    
    print_info(&format!("Verifying backup {}...", backup_id));
    
    // Perform verification
    match backup::verify_backup(backup_id) {
        Ok(true) => {
            print_success(&format!("Backup {} integrity verified successfully", backup_id));
            Ok(())
        },
        Ok(false) => {
            print_error(&format!("Backup {} is corrupted or has been tampered with", backup_id));
            Err(anyhow!("Backup verification failed"))
        },
        Err(e) => {
            print_error(&format!("Error verifying backup: {}", e));
            Err(e)
        }
    }
}

/// Delete a backup
pub fn delete_backup(auth: &AuthResult, backup_id: &str, force: bool) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_delete") {
        return Err(anyhow!("You don't have permission to delete backups"));
    }
    
    // Get backup details
    let backups = backup::list_backups()?;
    let backup_details = backups
        .iter()
        .find(|b| b.id == backup_id)
        .ok_or_else(|| anyhow!("Backup with ID {} not found", backup_id))?;
    
    // Confirm deletion if not forced
    if !force {
        print_warning("You are about to delete a backup. This action cannot be undone.");
        print_info(&format!(
            "Backup details:\n- ID: {}\n- Created: {}\n- Description: {}",
            backup_details.id,
            backup_details.created_at.format("%Y-%m-%d %H:%M:%S"),
            backup_details.description.as_deref().unwrap_or("None")
        ));
        
        print_warning("Are you sure you want to continue? (y/N): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            print_info("Deletion cancelled by user");
            return Ok(());
        }
    }
    
    // Delete the backup
    print_info(&format!("Deleting backup {}...", backup_id));
    backup::delete_backup(backup_id, Some(&auth.user.id))?;
    
    print_success(&format!("Backup {} deleted successfully", backup_id));
    Ok(())
}

/// Perform a partial restore of specific tables
pub fn partial_restore(auth: &AuthResult, backup_id: &str, tables_str: &str) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_restore") {
        return Err(anyhow!("You don't have permission to restore backups"));
    }
    
    // Parse tables
    let tables: Vec<&str> = tables_str.split(',').map(|s| s.trim()).collect();
    
    if tables.is_empty() {
        return Err(anyhow!("No tables specified for partial restore"));
    }
    
    // Get backup details
    let backups = backup::list_backups()?;
    let backup_details = backups
        .iter()
        .find(|b| b.id == backup_id)
        .ok_or_else(|| anyhow!("Backup with ID {} not found", backup_id))?;
    
    // Confirm restoration
    print_warning("You are about to partially restore the following tables:");
    for table in &tables {
        print_info(&format!("- {}", table));
    }
    print_warning("Current data in these tables will be replaced with data from the backup.");
    print_info(&format!(
        "Backup details:\n- ID: {}\n- Created: {}\n- Description: {}",
        backup_details.id,
        backup_details.created_at.format("%Y-%m-%d %H:%M:%S"),
        backup_details.description.as_deref().unwrap_or("None")
    ));
    
    print_warning("Are you sure you want to continue? (y/N): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if !input.trim().eq_ignore_ascii_case("y") {
        print_info("Partial restore cancelled by user");
        return Ok(());
    }
    
    // Perform the partial restoration
    print_info(&format!("Partially restoring tables from backup {}...", backup_id));
    backup::partial_restore(backup_id, &tables, Some(&auth.user.id))?;
    
    print_success("Tables restored successfully");
    Ok(())
}

/// Schedule an automatic backup
pub fn schedule_backup(auth: &AuthResult) -> Result<()> {
    // Check permissions
    if !auth.has_permission("backup_schedule") {
        return Err(anyhow!("You don't have permission to schedule backups"));
    }
    
    print_info("Scheduling automatic backup...");
    backup::schedule_automatic_backup()?;
    
    print_success("Automatic backup scheduled successfully");
    print_info("Note: In a production system, this would set up a recurring task.");
    print_info("For this implementation, a single backup was created.");
    
    Ok(())
}

/// Interactive backup creation
pub fn backup_interactive(auth: &AuthResult) -> Result<()> {
    let mut interactive = Interactive::new("Create Backup");
    
    let description = interactive.prompt("Enter a description for this backup (optional): ")?;
    let description = if description.trim().is_empty() { None } else { Some(description) };
    
    let custom_path = interactive.prompt("Do you want to save the backup to a custom location? (y/N): ")?;
    let output_path = if custom_path.trim().eq_ignore_ascii_case("y") {
        Some(interactive.prompt("Enter the output file path: ")?)
    } else {
        None
    };
    
    create_backup(
        auth, 
        output_path.as_deref(),
        description.as_deref()
    )
}

/// Interactive restore
pub fn restore_interactive(auth: &AuthResult) -> Result<()> {
    let mut interactive = Interactive::new("Restore Backup");
    
    // List available backups
    list_backups(auth)?;
    
    let backup_id = interactive.prompt("Enter the ID of the backup to restore: ")?;
    if backup_id.trim().is_empty() {
        return Err(anyhow!("No backup ID provided"));
    }
    
    restore_backup(auth, &backup_id, false)
}

/// Interactive partial restore
pub fn partial_restore_interactive(auth: &AuthResult) -> Result<()> {
    let mut interactive = Interactive::new("Partial Restore");
    
    // List available backups
    list_backups(auth)?;
    
    let backup_id = interactive.prompt("Enter the ID of the backup to restore from: ")?;
    if backup_id.trim().is_empty() {
        return Err(anyhow!("No backup ID provided"));
    }
    
    print_info("Enter the tables to restore, separated by commas (e.g., users,accounts,transactions):");
    let tables = interactive.prompt("Tables: ")?;
    if tables.trim().is_empty() {
        return Err(anyhow!("No tables specified"));
    }
    
    partial_restore(auth, &backup_id, &tables)
}

/// Helper function to format file size in human-readable format
fn format_size(size_bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if size_bytes < KB {
        format!("{} B", size_bytes)
    } else if size_bytes < MB {
        format!("{:.2} KB", size_bytes as f64 / KB as f64)
    } else if size_bytes < GB {
        format!("{:.2} MB", size_bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", size_bytes as f64 / GB as f64)
    }
} 