use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User role
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(UserRole::Admin),
            "user" => Ok(UserRole::User),
            _ => Err(format!("Invalid role: {}", s)),
        }
    }
}

/// User model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub salt: String,
    pub role: UserRole,
    pub failed_login_attempts: u32,
    pub account_locked: bool,
    pub lockout_time: Option<DateTime<Utc>>,
    pub last_login: Option<DateTime<Utc>>,
    pub password_changed: Option<DateTime<Utc>>,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, password_hash: String, salt: String, role: UserRole) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
            salt,
            role,
            failed_login_attempts: 0,
            account_locked: false,
            lockout_time: None,
            last_login: None,
            password_changed: Some(now),
            totp_secret: None,
            totp_enabled: false,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Account type
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AccountType {
    Checking,
    Savings,
}

impl AccountType {
    pub fn as_str(&self) -> &str {
        match self {
            AccountType::Checking => "checking",
            AccountType::Savings => "savings",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "checking" => Ok(AccountType::Checking),
            "savings" => Ok(AccountType::Savings),
            _ => Err(format!("Invalid account type: {}", s)),
        }
    }
}

/// Account status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AccountStatus {
    Active,
    Suspended,
    Closed,
}

impl AccountStatus {
    pub fn as_str(&self) -> &str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::Suspended => "suspended",
            AccountStatus::Closed => "closed",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "active" => Ok(AccountStatus::Active),
            "suspended" => Ok(AccountStatus::Suspended),
            "closed" => Ok(AccountStatus::Closed),
            _ => Err(format!("Invalid account status: {}", s)),
        }
    }
}

/// Account model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: String,
    pub user_id: String,
    pub account_type: AccountType,
    pub balance: f64,
    pub encrypted_details: Option<String>,
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Account {
    pub fn new(user_id: String, account_type: AccountType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            account_type,
            balance: 0.0,
            encrypted_details: None,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Transaction type
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionType {
    Deposit,
    Withdrawal,
    Transfer,
}

impl TransactionType {
    pub fn as_str(&self) -> &str {
        match self {
            TransactionType::Deposit => "deposit",
            TransactionType::Withdrawal => "withdrawal",
            TransactionType::Transfer => "transfer",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "deposit" => Ok(TransactionType::Deposit),
            "withdrawal" => Ok(TransactionType::Withdrawal),
            "transfer" => Ok(TransactionType::Transfer),
            _ => Err(format!("Invalid transaction type: {}", s)),
        }
    }
}

/// Transaction status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Completed,
    Failed,
    Reversed,
}

impl TransactionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TransactionStatus::Pending => "pending",
            TransactionStatus::Completed => "completed",
            TransactionStatus::Failed => "failed",
            TransactionStatus::Reversed => "reversed",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(TransactionStatus::Pending),
            "completed" => Ok(TransactionStatus::Completed),
            "failed" => Ok(TransactionStatus::Failed),
            "reversed" => Ok(TransactionStatus::Reversed),
            _ => Err(format!("Invalid transaction status: {}", s)),
        }
    }
}

/// Transaction model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub id: String,
    pub account_id: String,
    pub transaction_type: TransactionType,
    pub amount: f64,
    pub reference_id: Option<String>,
    pub encrypted_details: Option<String>,
    pub status: TransactionStatus,
    pub timestamp: DateTime<Utc>,
}

impl Transaction {
    pub fn new(
        account_id: String,
        transaction_type: TransactionType,
        amount: f64,
        reference_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            account_id,
            transaction_type,
            amount,
            reference_id,
            encrypted_details: None,
            status: TransactionStatus::Pending,
            timestamp: Utc::now(),
        }
    }
}

/// Audit event type
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AuditEventType {
    UserCreated,
    UserLogin,
    UserLoginFailed,
    UserLocked,
    UserUnlocked,
    UserPasswordChanged,
    TotpEnabled,
    TotpDisabled,
    AccountCreated,
    AccountUpdated,
    AccountStatusChanged,
    TransactionCreated,
    TransactionStatusChanged,
    TransactionReversed,
    ComplianceCheckCompleted,
    BackupCreated,
    BackupRestored,
    SecurityEvent,
}

impl AuditEventType {
    pub fn as_str(&self) -> &str {
        match self {
            AuditEventType::UserCreated => "user_created",
            AuditEventType::UserLogin => "user_login",
            AuditEventType::UserLoginFailed => "user_login_failed",
            AuditEventType::UserLocked => "user_locked",
            AuditEventType::UserUnlocked => "user_unlocked",
            AuditEventType::UserPasswordChanged => "user_password_changed",
            AuditEventType::TotpEnabled => "totp_enabled",
            AuditEventType::TotpDisabled => "totp_disabled",
            AuditEventType::AccountCreated => "account_created",
            AuditEventType::AccountUpdated => "account_updated",
            AuditEventType::AccountStatusChanged => "account_status_changed",
            AuditEventType::TransactionCreated => "transaction_created",
            AuditEventType::TransactionStatusChanged => "transaction_status_changed",
            AuditEventType::TransactionReversed => "transaction_reversed",
            AuditEventType::ComplianceCheckCompleted => "compliance_check_completed",
            AuditEventType::BackupCreated => "backup_created",
            AuditEventType::BackupRestored => "backup_restored",
            AuditEventType::SecurityEvent => "security_event",
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "user_created" => Ok(AuditEventType::UserCreated),
            "user_login" => Ok(AuditEventType::UserLogin),
            "user_login_failed" => Ok(AuditEventType::UserLoginFailed),
            "user_locked" => Ok(AuditEventType::UserLocked),
            "user_unlocked" => Ok(AuditEventType::UserUnlocked),
            "user_password_changed" => Ok(AuditEventType::UserPasswordChanged),
            "totp_enabled" => Ok(AuditEventType::TotpEnabled),
            "totp_disabled" => Ok(AuditEventType::TotpDisabled),
            "account_created" => Ok(AuditEventType::AccountCreated),
            "account_updated" => Ok(AuditEventType::AccountUpdated),
            "account_status_changed" => Ok(AuditEventType::AccountStatusChanged),
            "transaction_created" => Ok(AuditEventType::TransactionCreated),
            "transaction_status_changed" => Ok(AuditEventType::TransactionStatusChanged),
            "transaction_reversed" => Ok(AuditEventType::TransactionReversed),
            "compliance_check_completed" => Ok(AuditEventType::ComplianceCheckCompleted),
            "backup_created" => Ok(AuditEventType::BackupCreated),
            "backup_restored" => Ok(AuditEventType::BackupRestored),
            "security_event" => Ok(AuditEventType::SecurityEvent),
            _ => Err(format!("Invalid audit event type: {}", s)),
        }
    }
}

/// Audit log model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditLog {
    pub id: String,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub transaction_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: Option<String>,
    pub encrypted_details: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl AuditLog {
    pub fn new(
        event_type: AuditEventType,
        user_id: Option<String>,
        details: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            user_id,
            account_id: None,
            transaction_id: None,
            ip_address: None,
            details,
            encrypted_details: None,
            timestamp: Utc::now(),
        }
    }
} 