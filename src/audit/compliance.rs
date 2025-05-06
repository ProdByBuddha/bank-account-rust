use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use rusqlite::Connection;
use std::collections::HashMap;
use uuid::Uuid;

use crate::config;
use crate::database;
use crate::security;

/// Severity level for compliance issues
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Critical issues that must be fixed immediately
    Critical,
    /// Medium severity issues that should be addressed
    Warning,
    /// Informational issues
    Info
}

/// Compliance issue found during assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    pub code: String,
    pub name: String,
    pub message: String,
    pub severity: Severity,
    pub standard: String,
    pub remediation: Option<String>,
    pub reference: Option<String>
}

/// Passing compliance check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub code: String,
    pub name: String,
    pub standard: String,
    pub details: Option<String>
}

/// Results of a compliance check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub total_checks: usize,
    pub passing_checks: usize,
    pub failing_checks: usize,
    pub warning_checks: usize,
    pub issues: Vec<ComplianceIssue>,
    pub passing: Vec<ComplianceCheck>,
    pub standards: Vec<String>
}

/// Run a comprehensive compliance check
pub fn run_compliance_check(conn: &Connection) -> Result<ComplianceReport> {
    info!("Running comprehensive compliance check");
    
    let mut issues = Vec::new();
    let mut passing = Vec::new();
    let mut standards = Vec::new();
    
    // Add standards
    standards.push("PCI-DSS".to_string());
    standards.push("GDPR".to_string());
    standards.push("SOC 2".to_string());
    
    // Run all checks
    run_password_policy_checks(conn, &mut issues, &mut passing)?;
    run_data_retention_checks(conn, &mut issues, &mut passing)?;
    run_sensitive_data_checks(conn, &mut issues, &mut passing)?;
    run_encryption_checks(conn, &mut issues, &mut passing)?;
    run_audit_log_checks(conn, &mut issues, &mut passing)?;
    run_auth_checks(conn, &mut issues, &mut passing)?;
    run_backup_checks(conn, &mut issues, &mut passing)?;
    run_configuration_checks(conn, &mut issues, &mut passing)?;
    
    // Calculate statistics
    let total_checks = issues.len() + passing.len();
    let passing_checks = passing.len();
    let failing_checks = issues.iter().filter(|i| i.severity == Severity::Critical).count();
    let warning_checks = issues.iter().filter(|i| i.severity == Severity::Warning).count();
    
    let report = ComplianceReport {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        total_checks,
        passing_checks,
        failing_checks, 
        warning_checks,
        issues,
        passing,
        standards
    };
    
    // Save the report to the database
    save_report(conn, &report)?;
    
    info!("Compliance check completed. Total: {}, Passing: {}, Warnings: {}, Critical: {}", 
          total_checks, passing_checks, warning_checks, failing_checks);
    
    Ok(report)
}

/// Save compliance report to the database
fn save_report(conn: &Connection, report: &ComplianceReport) -> Result<()> {
    // Convert to JSON
    let json = serde_json::to_string(report)?;
    
    // Insert into database
    conn.execute(
        "INSERT INTO compliance_reports (id, timestamp, total_checks, passing_checks, 
        failing_checks, warning_checks, report_json) 
        VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            report.id,
            report.timestamp,
            report.total_checks,
            report.passing_checks,
            report.failing_checks,
            report.warning_checks,
            json
        ]
    ).context("Failed to save compliance report")?;
    
    info!("Saved compliance report with ID: {}", report.id);
    Ok(())
}

/// Run password policy compliance checks
fn run_password_policy_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check minimum password length
    if config.security.min_password_length < 8 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.2.3".to_string(),
            name: "Minimum Password Length".to_string(),
            message: format!("Minimum password length is set to {}, should be at least 8", 
                          config.security.min_password_length),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set minimum password length to at least 8 characters".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.2.3".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.2.3".to_string(),
            name: "Minimum Password Length".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Password length requirement is adequate ({})", config.security.min_password_length))
        });
    }
    
    // Check password complexity requirements
    if !config.security.require_complex_passwords {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.2.3".to_string(),
            name: "Password Complexity".to_string(),
            message: "Password complexity requirements are not enforced".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable complex password requirements in configuration".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.2.3".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.2.3-COMPLEX".to_string(),
            name: "Password Complexity".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Password complexity requirements are enforced".to_string())
        });
    }
    
    // Check password change frequency
    if config.security.password_expiry_days > 90 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.2.4".to_string(),
            name: "Password Change Frequency".to_string(),
            message: format!("Password expiry is set to {} days, should be maximum 90 days",
                          config.security.password_expiry_days),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set password expiry to 90 days or less".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.2.4".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.2.4".to_string(),
            name: "Password Change Frequency".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Password expiry period is adequate ({} days)", config.security.password_expiry_days))
        });
    }
    
    // Check account lockout settings
    if config.security.account_lockout_threshold > 6 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.1.6".to_string(),
            name: "Account Lockout Threshold".to_string(),
            message: format!("Account lockout threshold is set to {}, should be 6 or less attempts",
                          config.security.account_lockout_threshold),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set account lockout threshold to 6 or fewer failed attempts".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.1.6".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.1.6".to_string(),
            name: "Account Lockout Threshold".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Account lockout threshold is adequate ({} attempts)", 
                               config.security.account_lockout_threshold))
        });
    }
    
    Ok(())
}

/// Run data retention policy compliance checks
fn run_data_retention_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check transaction data retention
    let transaction_retention_days = match conn.query_row(
        "SELECT value FROM system_settings WHERE key = 'transaction_retention_days'",
        rusqlite::params![],
        |row| row.get::<_, i64>(0)
    ) {
        Ok(days) => days,
        Err(_) => config.data.transaction_retention_days // Use default if not set in DB
    };
    
    // For PCI-DSS, transaction data should be kept for at least 1 year
    if transaction_retention_days < 365 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.7".to_string(),
            name: "Transaction Data Retention".to_string(),
            message: format!("Transaction data retention is set to {} days, should be at least 365 days",
                          transaction_retention_days),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set transaction data retention to at least 365 days".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.7".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.7".to_string(),
            name: "Transaction Data Retention".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Transaction data retention is adequate ({} days)", transaction_retention_days))
        });
    }
    
    // Check audit log retention
    let audit_retention_days = config.audit.retention_days;
    
    // For PCI-DSS, audit logs should be kept for at least 1 year
    if audit_retention_days < 365 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.7-AUDIT".to_string(),
            name: "Audit Log Retention".to_string(),
            message: format!("Audit log retention is set to {} days, should be at least 365 days",
                          audit_retention_days),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set audit log retention to at least 365 days".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.7".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.7-AUDIT".to_string(),
            name: "Audit Log Retention".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Audit log retention is adequate ({} days)", audit_retention_days))
        });
    }
    
    // Check for data purging functionality
    let has_purge_function = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='data_purge_jobs'",
        rusqlite::params![],
        |row| row.get::<_, i64>(0)
    ).unwrap_or(0) > 0;
    
    if !has_purge_function {
        issues.push(ComplianceIssue {
            code: "GDPR-17".to_string(),
            name: "Data Deletion Capability".to_string(),
            message: "No data purging functionality implemented for GDPR right to erasure".to_string(),
            severity: Severity::Warning,
            standard: "GDPR".to_string(),
            remediation: Some("Implement data purging functionality for GDPR compliance".to_string()),
            reference: Some("GDPR Article 17, Right to erasure".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "GDPR-17".to_string(),
            name: "Data Deletion Capability".to_string(),
            standard: "GDPR".to_string(),
            details: Some("Data purging functionality is implemented".to_string())
        });
    }
    
    Ok(())
}

/// Run sensitive data classification and discovery checks
fn run_sensitive_data_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    // Check if encrypted columns are actually encrypted
    let encryption_check = conn.query_row(
        "SELECT COUNT(*) FROM transactions 
         WHERE encrypted_details IS NOT NULL 
         AND encrypted_details NOT LIKE '%ENCRYPTED:%'",
        rusqlite::params![],
        |row| row.get::<_, i64>(0)
    ).unwrap_or(0);
    
    if encryption_check > 0 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-3.4".to_string(),
            name: "Transaction Data Encryption".to_string(),
            message: format!("Found {} transactions with unencrypted sensitive data", encryption_check),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Ensure all sensitive transaction data is encrypted".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 3.4".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-3.4".to_string(),
            name: "Transaction Data Encryption".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("All sensitive transaction data appears to be encrypted".to_string())
        });
    }
    
    // Check for PII data classifications
    let has_pii_classification = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='data_classification'",
        rusqlite::params![],
        |row| row.get::<_, i64>(0)
    ).unwrap_or(0) > 0;
    
    if !has_pii_classification {
        issues.push(ComplianceIssue {
            code: "GDPR-30".to_string(),
            name: "PII Data Classification".to_string(),
            message: "No data classification system for personal data".to_string(),
            severity: Severity::Warning,
            standard: "GDPR".to_string(),
            remediation: Some("Implement data classification for personal information".to_string()),
            reference: Some("GDPR Article 30, Records of processing activities".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "GDPR-30".to_string(),
            name: "PII Data Classification".to_string(),
            standard: "GDPR".to_string(),
            details: Some("Data classification system is implemented".to_string())
        });
    }
    
    // Additional checks will be added in the next edit
    
    Ok(())
}

/// Run encryption policy and key management checks
fn run_encryption_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check key rotation policy
    let key_rotation_days = config.security.key_rotation_days;
    
    if key_rotation_days > 90 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-3.6.5".to_string(),
            name: "Encryption Key Rotation".to_string(),
            message: format!("Encryption key rotation interval is {} days, should be 90 days or less",
                         key_rotation_days),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set encryption key rotation interval to 90 days or less".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 3.6.5".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-3.6.5".to_string(),
            name: "Encryption Key Rotation".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Encryption key rotation interval is adequate ({} days)", key_rotation_days))
        });
    }
    
    // Check key strength
    let min_key_length = config.security.min_key_length;
    
    if min_key_length < 256 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-3.6.3".to_string(),
            name: "Encryption Key Strength".to_string(),
            message: format!("Minimum encryption key length is {} bits, should be at least 256 bits",
                         min_key_length),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Use AES-256 or equivalent strength cryptography".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 3.6.3".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-3.6.3".to_string(),
            name: "Encryption Key Strength".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Encryption key strength is adequate ({} bits)", min_key_length))
        });
    }
    
    // Check for encrypted database
    let db_encryption_enabled = config.database.encryption_enabled;
    
    if !db_encryption_enabled {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-3.4.1".to_string(),
            name: "Database Encryption".to_string(),
            message: "Database encryption is not enabled".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable transparent database encryption".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 3.4.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-3.4.1".to_string(),
            name: "Database Encryption".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Database encryption is enabled".to_string())
        });
    }
    
    // Check for secure key storage
    let secure_key_storage = config.security.secure_key_storage;
    
    if !secure_key_storage {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-3.6.1".to_string(),
            name: "Secure Key Storage".to_string(),
            message: "Secure key storage is not enabled".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable secure key storage using hardware security module or equivalent".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 3.6.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-3.6.1".to_string(),
            name: "Secure Key Storage".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Secure key storage is enabled".to_string())
        });
    }
    
    Ok(())
}

/// Run audit logging compliance checks
fn run_audit_log_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check if audit logging is enabled
    if !config.audit.enabled {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.1".to_string(),
            name: "Audit Logging".to_string(),
            message: "Audit logging is not enabled".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable audit logging in configuration".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.1".to_string(),
            name: "Audit Logging".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Audit logging is enabled".to_string())
        });
    }
    
    // Check if all required events are logged
    let required_events = vec![
        "login", "logout", "login_failure", "password_change",
        "account_create", "account_modify", "transaction", "security_change"
    ];
    
    let mut missing_events = Vec::new();
    
    for event in &required_events {
        // This would check if the event is actually logged in the system
        // For now, we'll assume some events are missing as an example
        if !config.audit.log_events.contains(&event.to_string()) {
            missing_events.push(event.to_string());
        }
    }
    
    if !missing_events.is_empty() {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.2".to_string(),
            name: "Audit Event Coverage".to_string(),
            message: format!("Missing audit logging for these events: {}", missing_events.join(", ")),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable audit logging for all required event types".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.2".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.2".to_string(),
            name: "Audit Event Coverage".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Audit logging covers all required event types".to_string())
        });
    }
    
    // Check for log integrity protection
    if !config.audit.enable_log_integrity {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.5.5".to_string(),
            name: "Audit Log Integrity".to_string(),
            message: "Audit log integrity protection is not enabled".to_string(),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable audit log integrity protection with checksums or signatures".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.5.5".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.5.5".to_string(),
            name: "Audit Log Integrity".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Audit log integrity protection is enabled".to_string())
        });
    }
    
    // Check if logs include all required fields
    let required_fields = vec![
        "timestamp", "user_id", "event_type", "source", "success_failure"
    ];
    
    let log_fields = config.audit.log_fields.clone();
    let mut missing_fields = Vec::new();
    
    for field in &required_fields {
        if !log_fields.contains(&field.to_string()) {
            missing_fields.push(field.to_string());
        }
    }
    
    if !missing_fields.is_empty() {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-10.3".to_string(),
            name: "Audit Log Fields".to_string(),
            message: format!("Audit logs missing required fields: {}", missing_fields.join(", ")),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Include all required fields in audit log entries".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 10.3".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-10.3".to_string(),
            name: "Audit Log Fields".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Audit logs include all required fields".to_string())
        });
    }
    
    Ok(())
}

/// Run authentication and authorization checks
fn run_auth_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check if 2FA is enforced for admin accounts
    if !config.security.require_2fa_for_admins {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.3".to_string(),
            name: "Multi-Factor Authentication - Admins".to_string(),
            message: "Multi-factor authentication is not required for administrative access".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enforce two-factor authentication for all admin users".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.3".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.3".to_string(),
            name: "Multi-Factor Authentication - Admins".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Multi-factor authentication is required for admin access".to_string())
        });
    }
    
    // Check if access control is properly implemented
    let has_rbac = config.security.enable_rbac;
    
    if !has_rbac {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-7.1".to_string(),
            name: "Role-Based Access Control".to_string(),
            message: "Role-based access control is not enabled".to_string(),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable role-based access control for system access".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 7.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-7.1".to_string(),
            name: "Role-Based Access Control".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Role-based access control is enabled".to_string())
        });
    }
    
    // Check if session timeout is properly configured
    let session_timeout = config.security.session_timeout_minutes;
    
    if session_timeout > 15 {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-8.1.8".to_string(),
            name: "Session Timeout".to_string(),
            message: format!("Session timeout is set to {} minutes, should be 15 minutes or less",
                         session_timeout),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Set session timeout to 15 minutes or less".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 8.1.8".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-8.1.8".to_string(),
            name: "Session Timeout".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some(format!("Session timeout is adequate ({} minutes)", session_timeout))
        });
    }
    
    // Check for proper JWT implementation
    let jwt_expiry_minutes = config.security.jwt_expiry_minutes;
    
    if jwt_expiry_minutes > 60 {
        issues.push(ComplianceIssue {
            code: "SOC2-CC7.1".to_string(),
            name: "JWT Token Expiry".to_string(),
            message: format!("JWT token expiry is set to {} minutes, should be 60 minutes or less",
                         jwt_expiry_minutes),
            severity: Severity::Warning,
            standard: "SOC 2".to_string(),
            remediation: Some("Set JWT token expiry to 60 minutes or less".to_string()),
            reference: Some("SOC 2 CC7.1 - User Authentication".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "SOC2-CC7.1".to_string(),
            name: "JWT Token Expiry".to_string(),
            standard: "SOC 2".to_string(),
            details: Some(format!("JWT token expiry is adequate ({} minutes)", jwt_expiry_minutes))
        });
    }
    
    Ok(())
}

/// Run backup and disaster recovery checks
fn run_backup_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check if backups are enabled
    if !config.backup.enabled {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-9.5".to_string(),
            name: "Data Backup".to_string(),
            message: "Automated data backups are not enabled".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable scheduled automated backups".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 9.5".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-9.5".to_string(),
            name: "Data Backup".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Automated data backups are enabled".to_string())
        });
    }
    
    // Check if backups are encrypted
    if !config.backup.encrypt_backups {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-9.5.1".to_string(),
            name: "Backup Encryption".to_string(),
            message: "Backups are not encrypted".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable encryption for all database backups".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 9.5.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-9.5.1".to_string(),
            name: "Backup Encryption".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Backups are encrypted".to_string())
        });
    }
    
    // Check if backup integrity checks are enabled
    if !config.backup.verify_integrity {
        issues.push(ComplianceIssue {
            code: "SOC2-CC9.1".to_string(),
            name: "Backup Integrity Verification".to_string(),
            message: "Backup integrity verification is not enabled".to_string(),
            severity: Severity::Warning,
            standard: "SOC 2".to_string(),
            remediation: Some("Enable integrity verification for all backups".to_string()),
            reference: Some("SOC 2 CC9.1 - Business Continuity".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "SOC2-CC9.1".to_string(),
            name: "Backup Integrity Verification".to_string(),
            standard: "SOC 2".to_string(),
            details: Some("Backup integrity verification is enabled".to_string())
        });
    }
    
    // Check backup frequency
    let backup_interval_hours = config.backup.interval_hours;
    
    if backup_interval_hours > 24 {
        issues.push(ComplianceIssue {
            code: "SOC2-CC9.1-FREQ".to_string(),
            name: "Backup Frequency".to_string(),
            message: format!("Backup interval is {} hours, should be 24 hours or less",
                         backup_interval_hours),
            severity: Severity::Warning,
            standard: "SOC 2".to_string(),
            remediation: Some("Schedule backups at least once per day".to_string()),
            reference: Some("SOC 2 CC9.1 - Business Continuity".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "SOC2-CC9.1-FREQ".to_string(),
            name: "Backup Frequency".to_string(),
            standard: "SOC 2".to_string(),
            details: Some(format!("Backup frequency is adequate ({} hours)", backup_interval_hours))
        });
    }
    
    Ok(())
}

/// Run security configuration validation checks
fn run_configuration_checks(
    conn: &Connection, 
    issues: &mut Vec<ComplianceIssue>,
    passing: &mut Vec<ComplianceCheck>
) -> Result<()> {
    let config = config::get_config();
    
    // Check if TLS is enforced for all connections
    if !config.security.enforce_tls {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-4.1".to_string(),
            name: "TLS Enforcement".to_string(),
            message: "TLS is not enforced for all connections".to_string(),
            severity: Severity::Critical,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Configure the application to require TLS for all connections".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 4.1".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-4.1".to_string(),
            name: "TLS Enforcement".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("TLS is enforced for all connections".to_string())
        });
    }
    
    // Check for vulnerability scanning
    if !config.security.enable_vulnerability_scan {
        issues.push(ComplianceIssue {
            code: "PCI-DSS-11.2".to_string(),
            name: "Vulnerability Scanning".to_string(),
            message: "Regular vulnerability scanning is not enabled".to_string(),
            severity: Severity::Warning,
            standard: "PCI-DSS".to_string(),
            remediation: Some("Enable regular vulnerability scanning".to_string()),
            reference: Some("PCI-DSS v3.2.1, Requirement 11.2".to_string())
        });
    } else {
        passing.push(ComplianceCheck {
            code: "PCI-DSS-11.2".to_string(),
            name: "Vulnerability Scanning".to_string(),
            standard: "PCI-DSS".to_string(),
            details: Some("Regular vulnerability scanning is enabled".to_string())
        });
    }
    
    Ok(())
}

/// Enforces data retention policy based on settings
pub fn enforce_data_retention_policy(conn: &Connection) -> Result<usize> {
    info!("Enforcing data retention policy");
    
    let config = config::get_config();
    let retention_days = config.data.transaction_retention_days;
    let now = Utc::now();
    let retention_date = now - Duration::days(retention_days);
    
    // Archive transactions older than retention period
    let rows = conn.execute(
        "UPDATE transactions 
         SET status = 'archived' 
         WHERE timestamp < ? 
         AND status = 'completed'",
        rusqlite::params![retention_date],
    )?;
    
    info!("Archived {} transactions based on retention policy", rows);
    
    Ok(rows)
}

/// Run data discovery to find potential unencrypted sensitive data
pub fn discover_sensitive_data(conn: &Connection) -> Result<Vec<HashMap<String, String>>> {
    info!("Running sensitive data discovery");
    
    let mut results = Vec::new();
    
    // Check for potential credit card numbers in unencrypted fields
    let mut stmt = conn.prepare(
        "SELECT id, details FROM transactions 
         WHERE details IS NOT NULL 
         AND details LIKE '%4%-%'
         AND details NOT LIKE 'ENCRYPTED:%'"
    )?;
    
    let rows = stmt.query_map(rusqlite::params![], |row| {
        let id: String = row.get(0)?;
        let details: String = row.get(1)?;
        
        let mut item = HashMap::new();
        item.insert("type".to_string(), "potential_card_number".to_string());
        item.insert("table".to_string(), "transactions".to_string());
        item.insert("id".to_string(), id);
        item.insert("field".to_string(), "details".to_string());
        
        Ok(item)
    })?;
    
    for row in rows {
        results.push(row?);
    }
    
    info!("Found {} potential instances of unencrypted sensitive data", results.len());
    
    Ok(results)
}

/// Generate a security report with all findings
pub fn generate_security_report(conn: &Connection) -> Result<String> {
    info!("Generating security report");
    
    // Run compliance check
    let compliance_report = run_compliance_check(conn)?;
    
    // Discover sensitive data
    let sensitive_data_findings = discover_sensitive_data(conn)?;
    
    // Generate report in JSON format
    let mut report = HashMap::new();
    report.insert("timestamp", Utc::now().to_string());
    report.insert("compliance_status", format!("{}% compliant", 
        (compliance_report.passing_checks as f64 / compliance_report.total_checks as f64) * 100.0));
    report.insert("critical_issues", compliance_report.failing_checks.to_string());
    report.insert("warnings", compliance_report.warning_checks.to_string());
    report.insert("sensitive_data_findings", sensitive_data_findings.len().to_string());
    
    // Add more detailed information
    let json = serde_json::to_string_pretty(&report)?;
    
    Ok(json)
} 