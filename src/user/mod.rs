// User management module
// This module provides functionality for user registration, authentication,
// and user profile management.

mod registration;
mod validation;
mod profile;
mod two_factor;  // New module for 2FA management

pub use registration::{register_user, UserRegistrationError};
pub use validation::{validate_password, PasswordRequirement, PasswordValidationError};
pub use profile::{get_user_profile, update_user_profile, UserProfileError};
pub use two_factor::{
    enable_2fa, verify_2fa_setup, disable_2fa, 
    verify_2fa_code, generate_backup_codes, use_backup_code,
    TwoFactorError
};

/// Max failed login attempts before account lockout
pub const MAX_FAILED_LOGIN_ATTEMPTS: u32 = 5;

/// Account lockout duration in minutes
pub const ACCOUNT_LOCKOUT_DURATION_MINUTES: i64 = 30;

/// Password expiry period in days
pub const PASSWORD_EXPIRY_DAYS: i64 = 90;

/// Minimum password length
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Email regex pattern for validation
pub const EMAIL_REGEX: &str = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"; 