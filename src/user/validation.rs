use anyhow::{Result, Context};
use regex::Regex;
use std::fmt;
use log::debug;
use crate::user::MIN_PASSWORD_LENGTH;

/// Password requirement types for validation
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordRequirement {
    MinimumLength(usize),
    ContainsUppercase,
    ContainsLowercase,
    ContainsNumbers,
    ContainsSpecialChars,
    NoCommonPatterns,
}

impl fmt::Display for PasswordRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordRequirement::MinimumLength(len) => write!(f, "Password must be at least {} characters long", len),
            PasswordRequirement::ContainsUppercase => write!(f, "Password must contain at least one uppercase letter"),
            PasswordRequirement::ContainsLowercase => write!(f, "Password must contain at least one lowercase letter"),
            PasswordRequirement::ContainsNumbers => write!(f, "Password must contain at least one number"),
            PasswordRequirement::ContainsSpecialChars => write!(f, "Password must contain at least one special character"),
            PasswordRequirement::NoCommonPatterns => write!(f, "Password must not contain common patterns or sequences"),
        }
    }
}

/// Password validation error
#[derive(Debug, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("Password validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Password policy requirements not met: {0}")]
    RequirementsNotMet(String),
    
    #[error("Password is too similar to user information")]
    TooSimilarToUserInfo,
    
    #[error("Internal validation error: {0}")]
    InternalError(String),
}

/// Validate a password against security requirements
pub fn validate_password(password: &str, username: Option<&str>) -> Result<(), PasswordValidationError> {
    debug!("Validating password strength");
    
    let mut failed_requirements = Vec::new();
    
    // Check minimum length
    if password.len() < MIN_PASSWORD_LENGTH {
        failed_requirements.push(PasswordRequirement::MinimumLength(MIN_PASSWORD_LENGTH));
    }
    
    // Check for uppercase letters
    if !password.chars().any(|c| c.is_uppercase()) {
        failed_requirements.push(PasswordRequirement::ContainsUppercase);
    }
    
    // Check for lowercase letters
    if !password.chars().any(|c| c.is_lowercase()) {
        failed_requirements.push(PasswordRequirement::ContainsLowercase);
    }
    
    // Check for numbers
    if !password.chars().any(|c| c.is_numeric()) {
        failed_requirements.push(PasswordRequirement::ContainsNumbers);
    }
    
    // Check for special characters
    let special_chars_regex = Regex::new(r"[^a-zA-Z0-9]").map_err(|e| {
        PasswordValidationError::InternalError(format!("Regex error: {}", e))
    })?;
    
    if !special_chars_regex.is_match(password) {
        failed_requirements.push(PasswordRequirement::ContainsSpecialChars);
    }
    
    // Check for common patterns
    if has_common_patterns(password) {
        failed_requirements.push(PasswordRequirement::NoCommonPatterns);
    }
    
    // Check for similarity to username if provided
    if let Some(username) = username {
        if password.to_lowercase().contains(&username.to_lowercase()) ||
           username.to_lowercase().contains(&password.to_lowercase()) {
            return Err(PasswordValidationError::TooSimilarToUserInfo);
        }
    }
    
    // If any requirements failed, return error
    if !failed_requirements.is_empty() {
        let requirements_str = failed_requirements
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        
        return Err(PasswordValidationError::RequirementsNotMet(requirements_str));
    }
    
    Ok(())
}

/// Check if password contains common patterns
fn has_common_patterns(password: &str) -> bool {
    let lower_password = password.to_lowercase();
    
    // Common sequences
    let sequences = [
        "123456", "abcdef", "qwerty", "password", "admin", "welcome",
        "abc123", "letmein", "monkey", "1234", "12345", "54321"
    ];
    
    for seq in &sequences {
        if lower_password.contains(seq) {
            return true;
        }
    }
    
    // Check for repeated characters (more than 3 times)
    let password_chars: Vec<char> = password.chars().collect();
    for i in 0..password_chars.len().saturating_sub(3) {
        if password_chars[i] == password_chars[i+1] &&
           password_chars[i] == password_chars[i+2] &&
           password_chars[i] == password_chars[i+3] {
            return true;
        }
    }
    
    // Check for keyboard sequences (horizontal)
    let keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ];
    
    for row in &keyboard_rows {
        let row_chars: Vec<char> = row.chars().collect();
        for i in 0..row_chars.len().saturating_sub(3) {
            let seq: String = row_chars[i..i+4].iter().collect();
            if lower_password.contains(&seq) {
                return true;
            }
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_validation_valid() {
        let password = "Str0ngP@ssw0rd!";
        assert!(validate_password(password, None).is_ok());
    }
    
    #[test]
    fn test_password_validation_too_short() {
        let password = "Short1!";
        let result = validate_password(password, None);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasswordValidationError::RequirementsNotMet(_))));
    }
    
    #[test]
    fn test_password_validation_no_uppercase() {
        let password = "strongp@ssw0rd!";
        let result = validate_password(password, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_password_validation_no_lowercase() {
        let password = "STRONG@P@SSW0RD!";
        let result = validate_password(password, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_password_validation_no_number() {
        let password = "StrongP@ssword!";
        let result = validate_password(password, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_password_validation_no_special_char() {
        let password = "StrongPassw0rd";
        let result = validate_password(password, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_password_validation_common_pattern() {
        let password = "StrongPassword123456!";
        let result = validate_password(password, None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_password_similar_to_username() {
        let password = "JohnDoe@123456!";
        let username = "johndoe";
        let result = validate_password(password, Some(username));
        assert!(result.is_err());
        assert!(matches!(result, Err(PasswordValidationError::TooSimilarToUserInfo)));
    }
} 