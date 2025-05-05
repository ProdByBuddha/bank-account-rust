# Developer Documentation for Rust Bank Account Management System

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Module Details](#module-details)
4. [Database Schema](#database-schema)
5. [Authentication and Security](#authentication-and-security)
6. [Development Environment Setup](#development-environment-setup)
7. [Testing Guidelines](#testing-guidelines)
8. [Coding Standards](#coding-standards)
9. [Contribution Guidelines](#contribution-guidelines)

## Architecture Overview

The Rust Bank Account Management System is built using a modular architecture that separates concerns into distinct components:

```
                         ┌─────────────────┐
                         │    CLI Layer    │
                         └───────┬─────────┘
                                 │
                         ┌───────▼─────────┐
                         │  Service Layer  │
                         └───────┬─────────┘
                                 │
┌──────────────┐   ┌─────────────┼─────────────┐   ┌─────────────┐
│  Security    │◄──┤  Data Access Layer (DAO)  ├──►│   Audit     │
│  Services    │   └─────────────┬─────────────┘   │   Logger    │
└──────────────┘                 │                 └─────────────┘
                        ┌────────▼────────┐
                        │ SQLite Database │
                        └─────────────────┘
```

### Core Design Principles

1. **Security-First Design**: Security is implemented at all levels, with encryption, access controls, and audit logging built into the core architecture.

2. **Modularity**: The system is divided into self-contained modules with clear boundaries and responsibilities.

3. **Command Pattern**: The CLI implements a command pattern approach to handle different operations.

4. **Repository Pattern**: Data access is abstracted through repository interfaces.

5. **Encryption by Default**: All sensitive data is encrypted both in transit and at rest.

## Project Structure

```
bank-account-rust/
├── src/
│   ├── main.rs                  # Application entry point
│   ├── cli/                     # Command-line interface code
│   │   ├── mod.rs               # CLI module definition
│   │   ├── auth.rs              # Authentication commands
│   │   ├── user.rs              # User management commands
│   │   ├── account.rs           # Account management commands
│   │   ├── security.rs          # Security-related commands
│   │   └── interactive.rs       # Interactive mode implementation
│   ├── user/                    # User management functionality
│   │   ├── mod.rs               # User module definition
│   │   ├── model.rs             # User data structures
│   │   ├── repository.rs        # User data access
│   │   └── service.rs           # User business logic
│   ├── account/                 # Account management functionality
│   │   ├── mod.rs               # Account module definition
│   │   ├── model.rs             # Account data structures
│   │   ├── repository.rs        # Account data access
│   │   └── service.rs           # Account business logic
│   ├── security/                # Security functionality
│   │   ├── mod.rs               # Security module definition
│   │   ├── encryption.rs        # Encryption utilities
│   │   ├── auth.rs              # Authentication logic
│   │   ├── token.rs             # JWT token handling
│   │   └── two_factor.rs        # 2FA implementation
│   ├── database/                # Database functionality
│   │   ├── mod.rs               # Database module definition
│   │   ├── connection.rs        # Connection management
│   │   ├── migration.rs         # Schema migration
│   │   └── models.rs            # Shared data models
│   ├── audit/                   # Audit logging functionality
│   │   ├── mod.rs               # Audit module definition
│   │   ├── logger.rs            # Audit logging implementation
│   │   └── repository.rs        # Audit data access
│   └── config/                  # Configuration handling
│       ├── mod.rs               # Config module definition
│       └── settings.rs          # Application settings
├── tests/                       # Integration tests
│   ├── user_tests.rs            # User functionality tests
│   ├── account_tests.rs         # Account functionality tests
│   └── security_tests.rs        # Security functionality tests
└── docs/                        # Documentation
    ├── user/                    # User documentation
    └── developer/               # Developer documentation
```

## Module Details

### CLI Module

The CLI module handles parsing and execution of command-line commands using Clap. Key components:

- **auth.rs**: Handles login, logout, and token management commands
- **user.rs**: Handles user creation, modification, and management commands
- **account.rs**: Handles account creation and transaction commands
- **security.rs**: Handles security-related commands like 2FA setup
- **interactive.rs**: Implements an interactive shell mode for the application

### User Module

The User module handles user management:

- **model.rs**: Defines the User struct and related types
- **repository.rs**: Implements database operations for users
- **service.rs**: Implements business logic for user operations

### Account Module

The Account module handles banking accounts and transactions:

- **model.rs**: Defines Account and Transaction structs
- **repository.rs**: Implements database operations for accounts and transactions
- **service.rs**: Implements business logic for account operations

### Security Module

The Security module provides encryption and authentication:

- **encryption.rs**: Implements AES-256 encryption/decryption
- **auth.rs**: Handles authentication logic
- **token.rs**: Implements JWT token generation and validation
- **two_factor.rs**: Implements TOTP-based two-factor authentication

### Database Module

The Database module handles database connections and operations:

- **connection.rs**: Manages database connections with connection pooling
- **migration.rs**: Handles database schema creation and updates
- **models.rs**: Defines shared database models and traits

### Audit Module

The Audit module provides comprehensive logging:

- **logger.rs**: Implements audit logging functionality
- **repository.rs**: Handles persistence of audit logs

### Config Module

The Config module handles application configuration:

- **settings.rs**: Loads and provides access to application settings

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_login TEXT,
    is_locked BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT 0
);
```

### Accounts Table
```sql
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_type TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Transactions Table
```sql
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    transaction_type TEXT NOT NULL,
    amount REAL NOT NULL,
    timestamp TEXT NOT NULL,
    description TEXT,
    encrypted_details TEXT,
    related_transaction_id INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts (id),
    FOREIGN KEY (related_transaction_id) REFERENCES transactions (id)
);
```

### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    timestamp TEXT NOT NULL,
    details TEXT NOT NULL,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Backup Codes Table
```sql
CREATE TABLE backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Trusted Devices Table
```sql
CREATE TABLE trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_identifier TEXT NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Authentication and Security

### Password Handling

- Passwords are hashed using Argon2id with the following parameters:
  - Memory: 19456 KiB
  - Iterations: 2
  - Parallelism: 1
  - Salt length: 16 bytes
  - Hash length: 32 bytes

### Token-based Authentication

- JSON Web Tokens (JWTs) are used for authentication
- Additional layer of JSON Web Encryption (JWE) protects sensitive claims
- Token expiration is set to 30 minutes by default
- Refresh tokens allow extending sessions without password re-entry

### Two-Factor Authentication

- Time-based One-Time Password (TOTP) implementation following RFC 6238
- 30-second time windows with ±1 window tolerance for time drift
- One-time backup codes for recovery if 2FA device is lost

### Data Encryption

- AES-256-GCM is used for encrypting sensitive data
- Database is encrypted at rest using SQLCipher
- Key derivation uses PBKDF2 with 100,000 iterations

## Development Environment Setup

### Prerequisites

- Rust 1.65.0 or later
- SQLite 3.8.0 or later
- OpenSSL 1.1.1 or later

### Setup Steps

1. Clone the repository:
   ```
   git clone https://github.com/your-username/bank-account-rust.git
   cd bank-account-rust
   ```

2. Create a development configuration:
   ```
   cp .env.example .env.development
   ```

3. Edit the `.env.development` file with your development settings.

4. Build the project:
   ```
   cargo build
   ```

5. Run tests:
   ```
   cargo test
   ```

6. Run the application in development mode:
   ```
   cargo run
   ```

### Development Workflows

#### Adding a New Command

1. Add a new function to the appropriate CLI module (e.g., `cli/user.rs`)
2. Register the command in the module's `register_commands` function
3. Implement the command's business logic in the corresponding service module
4. Add tests for the new functionality

#### Modifying the Database Schema

1. Create a new migration in `database/migration.rs`
2. Update the affected model structs
3. Update repository implementations for the affected models
4. Run tests to verify the migration works correctly

## Testing Guidelines

### Unit Tests

- All public functions should have unit tests
- Use mock implementations for dependencies
- Test both success and failure paths
- Aim for at least 80% code coverage

Example unit test:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[test]
    fn test_user_creation_success() {
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_create_user()
            .with(eq("testuser"), eq("password123"))
            .times(1)
            .returning(|_, _| Ok(User {
                id: 1,
                username: "testuser".to_string(),
                role: "user".to_string(),
                // other fields...
            }));
        
        let service = UserService::new(Box::new(mock_repo));
        let result = service.create_user("testuser", "password123");
        
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "testuser");
    }

    #[test]
    fn test_user_creation_duplicate_username() {
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_create_user()
            .with(eq("testuser"), eq("password123"))
            .times(1)
            .returning(|_, _| Err(Error::DuplicateUsername));
        
        let service = UserService::new(Box::new(mock_repo));
        let result = service.create_user("testuser", "password123");
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::DuplicateUsername);
    }
}
```

### Integration Tests

- Test end-to-end functionality
- Use a test database for integration tests
- Clean up after tests to ensure test isolation

### Security Tests

- Test authentication and authorization mechanisms
- Verify encryption functionality
- Test against common security vulnerabilities

## Coding Standards

### Style Guidelines

- Follow Rust standard style (enforced by rustfmt)
- Use meaningful variable and function names
- Add documentation comments for public APIs
- Keep functions small and focused on a single responsibility

### Error Handling

- Use custom error types with the `thiserror` crate
- Provide meaningful error messages
- Handle all potential errors explicitly
- Use `Result` types for functions that can fail

Example error type:
```rust
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Username already exists")]
    DuplicateUsername,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Unauthorized access")]
    Unauthorized,
    
    #[error("Insufficient funds")]
    InsufficientFunds,
    
    #[error("Invalid amount")]
    InvalidAmount,
    
    #[error("Account not found")]
    AccountNotFound,
    
    #[error("Account locked")]
    AccountLocked,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Invalid 2FA code")]
    Invalid2FACode,
}
```

### Performance Considerations

- Use connection pooling for database connections
- Implement appropriate indexing for database tables
- Profile and optimize critical operations
- Consider async operations for I/O-bound tasks

## Contribution Guidelines

### Pull Request Process

1. Fork the repository and create a feature branch
2. Implement your changes with accompanying tests
3. Ensure all tests pass and there are no linting errors
4. Create a pull request with a clear description of the changes
5. Reference any related issues in the pull request

### Commit Message Format

Follow the conventional commits specification:
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- feat: A new feature
- fix: A bug fix
- docs: Documentation changes
- style: Code style changes (formatting, etc.)
- refactor: Code changes that neither fix bugs nor add features
- perf: Performance improvements
- test: Adding or improving tests
- chore: Changes to the build process or auxiliary tools

Example:
```
feat(user): add email verification functionality

Implement email verification for new user registrations
including token generation, verification endpoints, and email templates.

Closes #123
``` 