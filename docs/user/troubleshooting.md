# Troubleshooting Guide

This guide addresses common issues you might encounter while using the Rust Bank Account Management System.

## Table of Contents
1. [Installation Issues](#installation-issues)
2. [Login Problems](#login-problems)
3. [Account Management Issues](#account-management-issues)
4. [Transaction Issues](#transaction-issues)
5. [Two-Factor Authentication Problems](#two-factor-authentication-problems)
6. [Database Issues](#database-issues)
7. [Error Code Reference](#error-code-reference)

## Installation Issues

### Error: Missing Dependencies

**Issue**: Error message indicating missing system dependencies during installation.

**Solution**:
- Ensure all prerequisites are installed:
  ```
  # For Debian/Ubuntu
  sudo apt-get install build-essential sqlite3 libsqlite3-dev libssl-dev

  # For macOS
  brew install sqlite openssl
  ```

### Error: Build Fails

**Issue**: The application fails to build with compilation errors.

**Solution**:
- Ensure you have the required version of Rust (1.65.0 or later):
  ```
  rustup update
  ```
- Clear cargo's cache and try rebuilding:
  ```
  cargo clean
  cargo build --release
  ```

### Error: Missing Configuration

**Issue**: Application starts but immediately exits with a configuration error.

**Solution**:
- Ensure you've created and properly configured the `.env` file:
  ```
  cp .env.example .env
  ```
- Open the `.env` file and verify all required settings are provided.

## Login Problems

### Error: "Authentication failed"

**Issue**: You're unable to log in despite using the correct username and password.

**Solutions**:
1. Ensure caps lock is off and you're using the correct username and password.
2. Check if your account is locked due to multiple failed attempts:
   ```
   ./target/release/bank-account-rust user status --username <your-username>
   ```
3. If locked, an administrator must unlock your account:
   ```
   ./target/release/bank-account-rust user unlock --username <your-username>
   ```

### Error: "Token expired"

**Issue**: You receive a token expired error during an operation.

**Solution**:
- Log out and log back in:
  ```
  ./target/release/bank-account-rust auth logout
  ./target/release/bank-account-rust auth login --username <your-username>
  ```

### Error: "No active session"

**Issue**: Commands fail with a "no active session" error.

**Solution**:
- Your session has expired or you're not logged in. Log in again:
  ```
  ./target/release/bank-account-rust auth login --username <your-username>
  ```

## Account Management Issues

### Error: "User already exists"

**Issue**: Unable to create a new user because the username already exists.

**Solution**:
- Choose a different username or have an administrator check if the user exists:
  ```
  ./target/release/bank-account-rust user exists --username <username>
  ```

### Error: "No permission to access this account"

**Issue**: You're trying to access an account that doesn't belong to you.

**Solution**:
- Verify you're using the correct account ID:
  ```
  ./target/release/bank-account-rust account list
  ```
- If you need access to someone else's account, you must have admin privileges.

### Error: "Cannot close account with non-zero balance"

**Issue**: Unable to close an account that still has funds.

**Solution**:
- Transfer or withdraw all funds before closing the account:
  ```
  ./target/release/bank-account-rust account withdraw --id <account-id> --amount <remaining-balance>
  ```

## Transaction Issues

### Error: "Insufficient funds"

**Issue**: Transaction fails because the account doesn't have enough money.

**Solution**:
- Check your current balance:
  ```
  ./target/release/bank-account-rust account info --id <account-id>
  ```
- Deposit funds or reduce the transaction amount.

### Error: "Transaction limit exceeded"

**Issue**: Transaction fails due to exceeding daily or transaction limits.

**Solution**:
- Check your account limits:
  ```
  ./target/release/bank-account-rust account limits --id <account-id>
  ```
- Try splitting the transaction into smaller amounts or contact an administrator to request a limit increase.

### Error: "Invalid transaction amount"

**Issue**: Transaction fails due to an invalid amount (negative, zero, or too many decimal places).

**Solution**:
- Ensure you're using a positive amount with a maximum of two decimal places.

## Two-Factor Authentication Problems

### Error: "Invalid 2FA code"

**Issue**: Your two-factor authentication code is being rejected.

**Solutions**:
1. Ensure your device's time is correctly synchronized (TOTP codes depend on accurate time).
2. Wait for a new code to be generated and try again.
3. If using a backup code, ensure you're entering it correctly.

### Error: "2FA required"

**Issue**: You're being prompted for 2FA but don't have your device.

**Solution**:
- Use one of your backup codes that was provided when you set up 2FA:
  ```
  ./target/release/bank-account-rust auth login --username <your-username> --backup-code <code>
  ```

### Error: "Cannot disable 2FA"

**Issue**: Unable to disable two-factor authentication.

**Solution**:
- You must provide a valid 2FA code to disable the feature:
  ```
  ./target/release/bank-account-rust security disable-2fa --code <current-2fa-code>
  ```

## Database Issues

### Error: "Database file is encrypted or is not a database"

**Issue**: The application cannot access the database.

**Solution**:
- Check your `.env` file to ensure the database path and encryption key are correctly set.
- The database may be corrupted. Try restoring from a backup:
  ```
  ./target/release/bank-account-rust database restore --backup <backup-path>
  ```

### Error: "Database is locked"

**Issue**: The application reports that the database is locked.

**Solution**:
- Ensure no other instances of the application are running.
- If the issue persists, try forcing the lock release (use with caution):
  ```
  ./target/release/bank-account-rust database force-unlock
  ```

## Error Code Reference

Here's a reference of error codes you might encounter, their meanings, and solutions:

| Error Code | Description | Solution |
|------------|-------------|----------|
| E1001 | Authentication failed | Verify credentials, check if account is locked |
| E1002 | Account locked | Contact administrator to unlock account |
| E1003 | Token expired | Log out and log back in |
| E1004 | Invalid 2FA code | Verify code, check device time synchronization |
| E2001 | Insufficient funds | Deposit funds or reduce transaction amount |
| E2002 | Transaction limit exceeded | Split transaction or request limit increase |
| E2003 | Invalid transaction amount | Use positive amount with max 2 decimal places |
| E3001 | Database access error | Check configuration, restore from backup |
| E3002 | Database locked | Ensure no other instances running, force unlock |
| E4001 | Permission denied | Verify you have appropriate permissions |
| E4002 | Resource not found | Check ID is correct and resource exists |
| E5001 | Configuration error | Verify `.env` file is properly set up |

## Still Need Help?

If you're experiencing an issue not covered in this guide:

1. Check the log file for more detailed error information:
   ```
   cat logs/app.log | tail -n 50
   ```

2. Generate a diagnostic report that can be shared with support:
   ```
   ./target/release/bank-account-rust system diagnostic-report --output report.txt
   ```

3. Contact the administrator with the error details and diagnostic report. 