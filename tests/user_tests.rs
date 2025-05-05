use bank_account_rust::{
    user::{
        model::User,
        service::UserService,
        repository::{UserRepository, MockUserRepository},
        error::Error as UserError,
    },
    security::password::{
        PasswordHasher, MockPasswordHasher,
    },
};
use mockall::predicate::*;

#[test]
fn test_create_user_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_create_user()
        .with(eq("testuser"), eq("hashed_password"), eq("salt"), eq("user"))
        .times(1)
        .returning(|username, _, _, role| {
            Ok(User {
                id: 1,
                username: username.to_string(),
                password_hash: "hashed_password".to_string(),
                salt: "salt".to_string(),
                role: role.to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_hash_password()
        .with(eq("password123"))
        .times(1)
        .returning(|_| Ok(("hashed_password".to_string(), "salt".to_string())));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.create_user("testuser", "password123", "user");

    // Assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.role, "user");
    assert_eq!(user.id, 1);
}

#[test]
fn test_create_user_duplicate_username() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_create_user()
        .with(eq("testuser"), eq("hashed_password"), eq("salt"), eq("user"))
        .times(1)
        .returning(|_, _, _, _| Err(UserError::DuplicateUsername));

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_hash_password()
        .with(eq("password123"))
        .times(1)
        .returning(|_| Ok(("hashed_password".to_string(), "salt".to_string())));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.create_user("testuser", "password123", "user");

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), UserError::DuplicateUsername);
}

#[test]
fn test_authenticate_user_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("testuser"))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "hashed_password".to_string(),
                salt: "salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    mock_repo
        .expect_update_login_success()
        .with(eq(1))
        .times(1)
        .returning(|_| Ok(()));

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_verify_password()
        .with(eq("password123"), eq("hashed_password"), eq("salt"))
        .times(1)
        .returning(|_, _, _| Ok(true));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.authenticate("testuser", "password123");

    // Assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.role, "user");
}

#[test]
fn test_authenticate_user_invalid_credentials() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("testuser"))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "hashed_password".to_string(),
                salt: "salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    mock_repo
        .expect_update_login_failure()
        .with(eq(1))
        .times(1)
        .returning(|_| Ok(()));

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_verify_password()
        .with(eq("wrong_password"), eq("hashed_password"), eq("salt"))
        .times(1)
        .returning(|_, _, _| Ok(false));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.authenticate("testuser", "wrong_password");

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), UserError::InvalidCredentials);
}

#[test]
fn test_authenticate_user_account_locked() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("testuser"))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "hashed_password".to_string(),
                salt: "salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 5,
                last_login: None,
                is_locked: true,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    let mut mock_hasher = MockPasswordHasher::new();
    
    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.authenticate("testuser", "password123");

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), UserError::AccountLocked);
}

#[test]
fn test_change_password_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_id()
        .with(eq(1))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "old_hash".to_string(),
                salt: "old_salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    mock_repo
        .expect_update_password()
        .with(eq(1), eq("new_hash"), eq("new_salt"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_verify_password()
        .with(eq("old_password"), eq("old_hash"), eq("old_salt"))
        .times(1)
        .returning(|_, _, _| Ok(true));

    mock_hasher
        .expect_hash_password()
        .with(eq("new_password"))
        .times(1)
        .returning(|_| Ok(("new_hash".to_string(), "new_salt".to_string())));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.change_password(1, "old_password", "new_password");

    // Assert
    assert!(result.is_ok());
}

#[test]
fn test_unlock_account_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("lockeduser"))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "lockeduser".to_string(),
                password_hash: "hash".to_string(),
                salt: "salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 5,
                last_login: None,
                is_locked: true,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    mock_repo
        .expect_unlock_account()
        .with(eq(1))
        .times(1)
        .returning(|_| Ok(()));

    let mock_hasher = MockPasswordHasher::new();
    
    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.unlock_account("lockeduser");

    // Assert
    assert!(result.is_ok());
}

#[test]
fn test_reset_password_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("testuser"))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "old_hash".to_string(),
                salt: "old_salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    mock_repo
        .expect_update_password()
        .with(eq(1), eq("new_hash"), eq("new_salt"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let mut mock_hasher = MockPasswordHasher::new();
    mock_hasher
        .expect_hash_password()
        .with(eq("new_password"))
        .times(1)
        .returning(|_| Ok(("new_hash".to_string(), "new_salt".to_string())));

    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.reset_password("testuser", "new_password");

    // Assert
    assert!(result.is_ok());
}

#[test]
fn test_user_not_found() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_username()
        .with(eq("nonexistent"))
        .times(1)
        .returning(|_| Err(UserError::UserNotFound));

    let mock_hasher = MockPasswordHasher::new();
    
    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.authenticate("nonexistent", "password123");

    // Assert
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), UserError::UserNotFound);
}

#[test]
fn test_get_user_by_id_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_by_id()
        .with(eq(1))
        .times(1)
        .returning(|_| {
            Ok(User {
                id: 1,
                username: "testuser".to_string(),
                password_hash: "hash".to_string(),
                salt: "salt".to_string(),
                role: "user".to_string(),
                failed_login_attempts: 0,
                last_login: None,
                is_locked: false,
                created_at: "2023-01-01T00:00:00Z".to_string(),
                updated_at: "2023-01-01T00:00:00Z".to_string(),
                totp_secret: None,
                totp_enabled: false,
            })
        });

    let mock_hasher = MockPasswordHasher::new();
    
    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.get_user_by_id(1);

    // Assert
    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.id, 1);
    assert_eq!(user.username, "testuser");
}

#[test]
fn test_get_all_users_success() {
    // Arrange
    let mut mock_repo = MockUserRepository::new();
    mock_repo
        .expect_find_all()
        .times(1)
        .returning(|| {
            Ok(vec![
                User {
                    id: 1,
                    username: "user1".to_string(),
                    password_hash: "hash1".to_string(),
                    salt: "salt1".to_string(),
                    role: "admin".to_string(),
                    failed_login_attempts: 0,
                    last_login: None,
                    is_locked: false,
                    created_at: "2023-01-01T00:00:00Z".to_string(),
                    updated_at: "2023-01-01T00:00:00Z".to_string(),
                    totp_secret: None,
                    totp_enabled: false,
                },
                User {
                    id: 2,
                    username: "user2".to_string(),
                    password_hash: "hash2".to_string(),
                    salt: "salt2".to_string(),
                    role: "user".to_string(),
                    failed_login_attempts: 0,
                    last_login: None,
                    is_locked: false,
                    created_at: "2023-01-01T00:00:00Z".to_string(),
                    updated_at: "2023-01-01T00:00:00Z".to_string(),
                    totp_secret: None,
                    totp_enabled: false,
                },
            ])
        });

    let mock_hasher = MockPasswordHasher::new();
    
    let service = UserService::new(Box::new(mock_repo), Box::new(mock_hasher));

    // Act
    let result = service.get_all_users();

    // Assert
    assert!(result.is_ok());
    let users = result.unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].username, "user1");
    assert_eq!(users[0].role, "admin");
    assert_eq!(users[1].username, "user2");
    assert_eq!(users[1].role, "user");
} 