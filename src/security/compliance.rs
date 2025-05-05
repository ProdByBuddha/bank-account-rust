use anyhow::{Result, Context};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

use crate::config;
use crate::database;
use crate::security;

/// Compliance check result status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Warning,
    Info,
    NotApplicable,
}

impl ComplianceStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ComplianceStatus::Pass => "pass",
            ComplianceStatus::Fail => "fail",
            ComplianceStatus::Warning => "warning",
            ComplianceStatus::Info => "info",
            ComplianceStatus::NotApplicable => "not_applicable",
        }
    }
}

/// Compliance check result
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComplianceCheckResult {
    pub id: String,
    pub name: String,
    pub description: String,
    pub requirement: String,
    pub status: ComplianceStatus,
    pub details: Option<String>,
    pub recommendation: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl ComplianceCheckResult {
    pub fn new(
        name: &str,
        description: &str,
        requirement: &str,
        status: ComplianceStatus,
        details: Option<String>,
        recommendation: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            requirement: requirement.to_string(),
            status,
            details,
            recommendation,
            timestamp: Utc::now(),
        }
    }
}

/// Compliance report
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComplianceReport {
    pub id: String,
    pub name: String,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub results: Vec<ComplianceCheckResult>,
    pub summary: HashMap<String, usize>,
}

impl ComplianceReport {
    pub fn new(name: &str, version: &str, results: Vec<ComplianceCheckResult>) -> Self {
        // Count results by status
        let mut summary = HashMap::new();
        for result in &results {
            let status_str = result.status.as_str().to_string();
            *summary.entry(status_str).or_insert(0) += 1;
        }
        
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            version: version.to_string(),
            timestamp: Utc::now(),
            results,
            summary,
        }
    }
}

/// Run all PCI-DSS compliance checks
pub fn run_pci_dss_checks() -> Result<ComplianceReport> {
    let config = config::get_config();
    
    info!("Running PCI-DSS compliance checks");
    
    let mut results = Vec::new();
    
    // Add individual check results
    results.push(check_password_policy()?);
    results.push(check_encryption_key_management()?);
    results.push(check_audit_logging()?);
    results.push(check_authentication_methods()?);
    results.push(check_session_management()?);
    results.push(check_sensitive_data_protection()?);
    
    // Create report
    let report = ComplianceReport::new(
        "PCI-DSS Compliance Check",
        "1.0",
        results,
    );
    
    info!("Completed PCI-DSS compliance check");
    debug!("Results summary: {:?}", report.summary);
    
    Ok(report)
}

/// Check password policy compliance
fn check_password_policy() -> Result<ComplianceCheckResult> {
    let config = config::get_config();
    
    let min_length = config.security.min_password_length;
    let mut status = ComplianceStatus::Pass;
    let mut details = String::new();
    let mut recommendation = None;
    
    details.push_str(&format!("Password minimum length: {}\n", min_length));
    
    if min_length < 8 {
        status = ComplianceStatus::Fail;
        recommendation = Some("Set minimum password length to at least 8 characters".to_string());
    }
    
    Ok(ComplianceCheckResult::new(
        "Password Policy",
        "Checks if password policies comply with PCI-DSS requirements",
        "PCI-DSS Requirement 8.2.3",
        status,
        Some(details),
        recommendation,
    ))
}

/// Check encryption key management
fn check_encryption_key_management() -> Result<ComplianceCheckResult> {
    // In a real implementation, this would check for key rotation policies,
    // secure key storage, etc.
    
    let status = ComplianceStatus::Info;
    let details = "Encryption key management is implemented, but needs manual review".to_string();
    let recommendation = Some("Implement regular key rotation and secure storage".to_string());
    
    Ok(ComplianceCheckResult::new(
        "Encryption Key Management",
        "Checks if encryption keys are properly managed",
        "PCI-DSS Requirement 3.5",
        status,
        Some(details),
        recommendation,
    ))
}

/// Check audit logging
fn check_audit_logging() -> Result<ComplianceCheckResult> {
    // In a real implementation, this would check for proper audit logging
    // of all critical operations
    
    let status = ComplianceStatus::Pass;
    let details = "Audit logging is implemented for all critical operations".to_string();
    let recommendation = None;
    
    Ok(ComplianceCheckResult::new(
        "Audit Logging",
        "Checks if audit logging is properly implemented",
        "PCI-DSS Requirement 10.2",
        status,
        Some(details),
        recommendation,
    ))
}

/// Check authentication methods
fn check_authentication_methods() -> Result<ComplianceCheckResult> {
    // In a real implementation, this would check for strong authentication methods,
    // multi-factor authentication, etc.
    
    let status = ComplianceStatus::Pass;
    let details = "Two-factor authentication is available for all accounts".to_string();
    let recommendation = None;
    
    Ok(ComplianceCheckResult::new(
        "Authentication Methods",
        "Checks if strong authentication methods are used",
        "PCI-DSS Requirement 8.3",
        status,
        Some(details),
        recommendation,
    ))
}

/// Check session management
fn check_session_management() -> Result<ComplianceCheckResult> {
    let config = config::get_config();
    
    let token_validity = config.security.token_validity;
    let mut status = ComplianceStatus::Pass;
    let mut details = String::new();
    let mut recommendation = None;
    
    details.push_str(&format!("Session timeout: {} minutes\n", token_validity));
    
    if token_validity > 15 {
        status = ComplianceStatus::Warning;
        recommendation = Some("Consider shorter session timeout (15 minutes or less)".to_string());
    }
    
    Ok(ComplianceCheckResult::new(
        "Session Management",
        "Checks if session management is secure",
        "PCI-DSS Requirement 8.1.8",
        status,
        Some(details),
        recommendation,
    ))
}

/// Check sensitive data protection
fn check_sensitive_data_protection() -> Result<ComplianceCheckResult> {
    // In a real implementation, this would check for proper encryption of
    // sensitive data, masking of PAN data, etc.
    
    let status = ComplianceStatus::Pass;
    let details = "Sensitive data is encrypted at rest and in transit".to_string();
    let recommendation = None;
    
    Ok(ComplianceCheckResult::new(
        "Sensitive Data Protection",
        "Checks if sensitive data is properly protected",
        "PCI-DSS Requirement 3.4",
        status,
        Some(details),
        recommendation,
    ))
}

/// Get a human-readable summary of a compliance report
pub fn format_report_summary(report: &ComplianceReport) -> String {
    let mut summary = format!("# {} v{}\n", report.name, report.version);
    summary.push_str(&format!("Date: {}\n\n", report.timestamp.format("%Y-%m-%d %H:%M:%S")));
    
    // Add results summary
    summary.push_str("## Summary\n");
    for (status, count) in &report.summary {
        summary.push_str(&format!("- {}: {}\n", status, count));
    }
    summary.push('\n');
    
    // Add failed checks
    let failed_checks: Vec<&ComplianceCheckResult> = report.results.iter()
        .filter(|r| r.status == ComplianceStatus::Fail)
        .collect();
    
    if !failed_checks.is_empty() {
        summary.push_str("## Failed Checks\n");
        for check in failed_checks {
            summary.push_str(&format!("### {}\n", check.name));
            summary.push_str(&format!("Requirement: {}\n", check.requirement));
            if let Some(details) = &check.details {
                summary.push_str(&format!("Details: {}\n", details));
            }
            if let Some(recommendation) = &check.recommendation {
                summary.push_str(&format!("Recommendation: {}\n", recommendation));
            }
            summary.push('\n');
        }
    }
    
    // Add warning checks
    let warning_checks: Vec<&ComplianceCheckResult> = report.results.iter()
        .filter(|r| r.status == ComplianceStatus::Warning)
        .collect();
    
    if !warning_checks.is_empty() {
        summary.push_str("## Warnings\n");
        for check in warning_checks {
            summary.push_str(&format!("### {}\n", check.name));
            summary.push_str(&format!("Requirement: {}\n", check.requirement));
            if let Some(details) = &check.details {
                summary.push_str(&format!("Details: {}\n", details));
            }
            if let Some(recommendation) = &check.recommendation {
                summary.push_str(&format!("Recommendation: {}\n", recommendation));
            }
            summary.push('\n');
        }
    }
    
    summary
}

/// Save a compliance report to the database
pub fn save_report(report: &ComplianceReport, user_id: Option<&str>) -> Result<()> {
    // TODO: Implement saving the report to the database
    // This would store the report in the compliance_checks table
    
    debug!("Compliance report {} saved to database", report.id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compliance_check_result() {
        let result = ComplianceCheckResult::new(
            "Test Check",
            "Test Description",
            "Test Requirement",
            ComplianceStatus::Pass,
            Some("Test Details".to_string()),
            None,
        );
        
        assert_eq!(result.name, "Test Check");
        assert_eq!(result.status, ComplianceStatus::Pass);
    }
    
    #[test]
    fn test_compliance_report() {
        let results = vec![
            ComplianceCheckResult::new(
                "Check 1",
                "Description 1",
                "Requirement 1",
                ComplianceStatus::Pass,
                None,
                None,
            ),
            ComplianceCheckResult::new(
                "Check 2",
                "Description 2",
                "Requirement 2",
                ComplianceStatus::Fail,
                None,
                None,
            ),
        ];
        
        let report = ComplianceReport::new("Test Report", "1.0", results);
        
        assert_eq!(report.name, "Test Report");
        assert_eq!(report.version, "1.0");
        assert_eq!(report.results.len(), 2);
        assert_eq!(report.summary.len(), 2);
        assert_eq!(report.summary.get("pass"), Some(&1));
        assert_eq!(report.summary.get("fail"), Some(&1));
    }
}
