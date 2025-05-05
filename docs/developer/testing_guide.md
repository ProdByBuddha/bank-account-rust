# Testing Guide for Rust Bank Account Management System

This guide provides detailed instructions and examples for testing the various components of the Bank Account Management System.

## Table of Contents
1. [Testing Philosophy](#testing-philosophy)
2. [Test Types](#test-types)
3. [Testing Tools](#testing-tools)
4. [Writing Unit Tests](#writing-unit-tests)
5. [Writing Integration Tests](#writing-integration-tests)
6. [Security Testing](#security-testing)
7. [Performance Testing](#performance-testing)
8. [Test Coverage](#test-coverage)
9. [Continuous Integration](#continuous-integration)

## Testing Philosophy

Our testing approach follows these key principles:

1. **Test-Driven Development**: Write tests before implementing features when possible
2. **Comprehensive Coverage**: Aim for >80% code coverage for all critical modules
3. **Security Verification**: Specific tests for security-critical features
4. **Realistic Scenarios**: Test real-world user flows and edge cases
5. **Automated Testing**: All tests should be automated and repeatable

## Test Types

### Unit Tests

Tests for individual functions and methods in isolation, mocking all dependencies.

### Integration Tests

Tests that verify multiple components work together correctly.

### Security Tests

Specialized tests focusing on authentication, authorization, encryption, and other security features.

### Performance Tests

Tests that measure and verify the performance of critical operations.

## Testing Tools

- **Testing Framework**: Rust's built-in test framework
- **Mocking**: `mockall` crate for creating mock objects
- **Assertions**: `assert_eq!`, `assert!`, etc.
- **Coverage**: `cargo-tarpaulin` for measuring test coverage
- **Fuzzing**: `cargo-fuzz` for finding edge cases via randomized inputs

## Writing Unit Tests

### Test Structure

Unit tests should follow this structure:

1. **Arrange**: Set up the test environment and test data
2. **Act**: Call the function being tested
3. **Assert**: Verify the function behaves as expected

### Example Unit Tests by Module

#### User Module

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[test]
    fn test_create_user_success() {
        // Arrange
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
        
        // Act
        let result = service.create_user("testuser", "password123");
        
        // Assert
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.role, "user");
    }

    #[test]
    fn test_create_user_duplicate_username() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_create_user()
            .with(eq("testuser"), eq("password123"))
            .times(1)
            .returning(|_, _| Err(Error::DuplicateUsername));
        
        let service = UserService::new(Box::new(mock_repo));
        
        // Act
        let result = service.create_user("testuser", "password123");
        
        // Assert
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::DuplicateUsername);
    }

    #[test]
    fn test_authenticate_user_success() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        mock_repo
            .expect_find_by_username()
            .with(eq("testuser"))
            .times(1)
            .returning(|_| Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "hashed_password".to_string(),
                salt: "salt".to_string(),
                failed_login_attempts: 0,
                is_locked: false,
                // other fields...
            }));
        
        let mut mock_password_hasher = MockPasswordHasher::new();
        mock_password_hasher
            .expect_verify_password()
            .with(eq("password123"), eq("hashed_password"), eq("salt"))
            .times(1)
            .returning(|_, _, _| Ok(true));
        
        let service = UserService::new(
            Box::new(mock_repo),
            Box::new(mock_password_hasher)
        );
        
        // Act
        let result = service.authenticate("testuser", "password123");
        
        // Assert
        assert!(result.is_ok());
    }
}
```

#### Account Module

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[test]
    fn test_create_account_success() {
        // Arrange
        let mut mock_repo = MockAccountRepository::new();
        mock_repo
            .expect_create_account()
            .with(eq(1), eq("checking"))
            .times(1)
            .returning(|_, _| Ok(Account {
                id: 1,
                user_id: 1,
                account_type: "checking".to_string(),
                balance: 0.0,
                status: "active".to_string(),
                // other fields...
            }));
        
        let service = AccountService::new(Box::new(mock_repo));
        
        // Act
        let result = service.create_account(1, "checking");
        
        // Assert
        assert!(result.is_ok());
        let account = result.unwrap();
        assert_eq!(account.user_id, 1);
        assert_eq!(account.account_type, "checking");
        assert_eq!(account.balance, 0.0);
    }

    #[test]
    fn test_deposit_success() {
        // Arrange
        let mut mock_repo = MockAccountRepository::new();
        mock_repo
            .expect_find_by_id()
            .with(eq(1))
            .times(1)
            .returning(|_| Ok(Account {
                id: 1,
                user_id: 1,
                account_type: "checking".to_string(),
                balance: 100.0,
                status: "active".to_string(),
                // other fields...
            }));
        
        mock_repo
            .expect_update_balance()
            .with(eq(1), eq(150.0))
            .times(1)
            .returning(|_, _| Ok(()));
        
        mock_repo
            .expect_record_transaction()
            .with(eq(1), eq("deposit"), eq(50.0), any::<String>(), any::<Option<String>>())
            .times(1)
            .returning(|_, _, _, _, _| Ok(Transaction {
                id: 1,
                account_id: 1,
                transaction_type: "deposit".to_string(),
                amount: 50.0,
                // other fields...
            }));
        
        let service = AccountService::new(Box::new(mock_repo));
        
        // Act
        let result = service.deposit(1, 50.0, "Test deposit");
        
        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_withdraw_insufficient_funds() {
        // Arrange
        let mut mock_repo = MockAccountRepository::new();
        mock_repo
            .expect_find_by_id()
            .with(eq(1))
            .times(1)
            .returning(|_| Ok(Account {
                id: 1,
                user_id: 1,
                account_type: "checking".to_string(),
                balance: 50.0,
                status: "active".to_string(),
                // other fields...
            }));
        
        let service = AccountService::new(Box::new(mock_repo));
        
        // Act
        let result = service.withdraw(1, 100.0, "Test withdrawal");
        
        // Assert
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InsufficientFunds);
    }
}
```

#### Security Module

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_success() {
        // Arrange
        let encryption_service = EncryptionService::new("test_key".to_string());
        let plain_text = "sensitive data";
        
        // Act
        let encrypted = encryption_service.encrypt(plain_text).unwrap();
        let decrypted = encryption_service.decrypt(&encrypted).unwrap();
        
        // Assert
        assert_ne!(plain_text, encrypted);
        assert_eq!(plain_text, decrypted);
    }

    #[test]
    fn test_jwt_token_generation_validation() {
        // Arrange
        let token_service = TokenService::new("secret_key".to_string(), 30);
        let claims = Claims {
            sub: "user123".to_string(),
            role: "user".to_string(),
            exp: time::OffsetDateTime::now_utc().unix_timestamp() + 1800,
        };
        
        // Act
        let token = token_service.generate_token(&claims).unwrap();
        let validated_claims = token_service.validate_token(&token).unwrap();
        
        // Assert
        assert_eq!(validated_claims.sub, "user123");
        assert_eq!(validated_claims.role, "user");
    }
    
    #[test]
    fn test_password_hashing() {
        // Arrange
        let password_service = PasswordService::new();
        let password = "secure_password";
        
        // Act
        let (hash, salt) = password_service.hash_password(password).unwrap();
        let is_valid = password_service.verify_password(password, &hash, &salt).unwrap();
        
        // Assert
        assert!(is_valid);
    }
    
    #[test]
    fn test_totp_generation_validation() {
        // Arrange
        let totp_service = TotpService::new();
        let secret = totp_service.generate_secret().unwrap();
        
        // Act
        let code = totp_service.generate_code(&secret).unwrap();
        let is_valid = totp_service.verify_code(&secret, &code).unwrap();
        
        // Assert
        assert!(is_valid);
    }
}
```

## Writing Integration Tests

Integration tests should be placed in the `tests/` directory. These tests verify that multiple components work together correctly.

### Example Integration Test

```rust
// In tests/account_integration_test.rs
use bank_account_rust::{
    config::Settings,
    database::Connection,
    user::UserService,
    account::AccountService,
};

#[test]
fn test_create_account_and_deposit() {
    // Setup
    let settings = Settings::test();
    let db = Connection::new(&settings.database_url).unwrap();
    db.setup_test_database().unwrap();
    
    let user_service = UserService::new(&db);
    let account_service = AccountService::new(&db);
    
    // Create a user
    let user = user_service.create_user("test_user", "password123").unwrap();
    
    // Create an account
    let account = account_service.create_account(user.id, "checking").unwrap();
    
    // Deposit money
    let transaction = account_service.deposit(account.id, 100.0, "Initial deposit").unwrap();
    
    // Verify account balance
    let updated_account = account_service.get_account(account.id).unwrap();
    assert_eq!(updated_account.balance, 100.0);
    
    // Verify transaction details
    assert_eq!(transaction.account_id, account.id);
    assert_eq!(transaction.amount, 100.0);
    assert_eq!(transaction.transaction_type, "deposit");
    
    // Cleanup
    db.teardown_test_database().unwrap();
}
```

## Security Testing

Security tests should verify that the application's security features work as expected.

### Authentication Testing

```rust
#[test]
fn test_authentication_with_rate_limiting() {
    // Setup
    let settings = Settings::test();
    let db = Connection::new(&settings.database_url).unwrap();
    db.setup_test_database().unwrap();
    
    let user_service = UserService::new(&db);
    let auth_service = AuthService::new(&db);
    
    // Create a user
    user_service.create_user("security_test", "password123").unwrap();
    
    // Test successful authentication
    let token = auth_service.login("security_test", "password123").unwrap();
    assert!(auth_service.validate_token(&token).is_ok());
    
    // Test failed authentication with rate limiting
    for _ in 0..5 {
        let result = auth_service.login("security_test", "wrong_password");
        assert!(result.is_err());
    }
    
    // After 5 failures, the account should be locked
    let result = auth_service.login("security_test", "password123");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::AccountLocked);
    
    // Cleanup
    db.teardown_test_database().unwrap();
}
```

### Encryption Testing

```rust
#[test]
fn test_database_encryption() {
    // Setup
    let settings = Settings::test();
    let db = Connection::new(&settings.database_url).unwrap();
    db.setup_test_database().unwrap();
    
    // Create a user with encrypted fields
    let user_id = db.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
        params!["encryption_test", "hash", "salt"],
    ).unwrap();
    
    // Insert sensitive data
    let transaction_query = "INSERT INTO transactions (account_id, transaction_type, amount, timestamp, encrypted_details) VALUES (?, ?, ?, ?, ?)";
    db.execute(
        transaction_query,
        params![1, "deposit", 100.0, "2023-01-01", "encrypted_data"],
    ).unwrap();
    
    // Read the raw database file and verify encryption
    let db_contents = std::fs::read_to_string(&settings.database_url).unwrap();
    assert!(!db_contents.contains("encrypted_data"));
    
    // Cleanup
    db.teardown_test_database().unwrap();
}
```

## Performance Testing

Performance tests measure and verify the speed and resource usage of critical operations.

```rust
#[test]
fn test_transaction_performance() {
    // Setup
    let settings = Settings::test();
    let db = Connection::new(&settings.database_url).unwrap();
    db.setup_test_database().unwrap();
    
    let account_service = AccountService::new(&db);
    let account_id = db.execute(
        "INSERT INTO accounts (user_id, account_type, balance) VALUES (?, ?, ?)",
        params![1, "checking", 10000.0],
    ).unwrap();
    
    // Measure transaction time
    let start = std::time::Instant::now();
    for i in 0..100 {
        account_service.deposit(account_id, 10.0, &format!("Deposit {}", i)).unwrap();
    }
    let duration = start.elapsed();
    
    // Assert performance is within acceptable limits
    assert!(duration.as_millis() < 5000); // Should complete 100 transactions in under 5 seconds
    
    // Cleanup
    db.teardown_test_database().unwrap();
}
```

## Test Coverage

Use `cargo-tarpaulin` to measure test coverage:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

Ensure critical security modules have at least 90% coverage, and aim for 80% coverage overall.

## Continuous Integration

Our CI pipeline runs all tests for every pull request and ensures:

1. All tests pass
2. Code coverage meets targets
3. No security vulnerabilities in dependencies
4. Code formatting follows standards

### CI Configuration

Tests are run in the CI pipeline using this command:

```bash
cargo test --all-features
```

Coverage is checked with:

```bash
cargo tarpaulin --out Xml
bash <(curl -s https://codecov.io/bash)
```

### Local CI Checks

Before submitting a PR, run these checks locally:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Run tests
cargo test

# Check coverage
cargo tarpaulin
``` 