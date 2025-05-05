# User Documentation for Rust Bank Account Management System

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Features](#features)
   - [User Management](#user-management)
   - [Account Management](#account-management)
   - [Transaction Operations](#transaction-operations)
   - [Security Features](#security-features)
5. [Security Guidelines](#security-guidelines)
6. [Troubleshooting](#troubleshooting)
7. [FAQs](#faqs)

## Introduction

The Rust Bank Account Management System is a secure command-line banking application designed to provide robust financial management capabilities with a strong focus on security. This application allows users to create accounts, manage transactions, and maintain financial records with industry-standard security practices.

## Installation

### Prerequisites
- Rust (1.65.0 or later)
- SQLite 3.8.0 or later
- OpenSSL 1.1.1 or later

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/your-username/bank-account-rust.git
   cd bank-account-rust
   ```

2. Create a configuration file:
   ```
   cp .env.example .env
   ```

3. Edit the `.env` file with your preferred configuration settings.

4. Build the application:
   ```
   cargo build --release
   ```

5. Run the application:
   ```
   ./target/release/bank-account-rust
   ```

## Getting Started

### First-time Setup

1. **Create an admin user**:
   ```
   ./target/release/bank-account-rust user create --username admin --role admin
   ```
   Follow the prompts to set a secure password.

2. **Log in**:
   ```
   ./target/release/bank-account-rust auth login --username admin
   ```

3. **Create a regular user account**:
   ```
   ./target/release/bank-account-rust user create --username customer1
   ```

4. **Create a bank account**:
   ```
   ./target/release/bank-account-rust account create --type checking --username customer1
   ```

### Basic Commands Overview

- **Help**: To see available commands
  ```
  ./target/release/bank-account-rust --help
  ```

- **Login**:
  ```
  ./target/release/bank-account-rust auth login --username <your-username>
  ```

- **Logout**:
  ```
  ./target/release/bank-account-rust auth logout
  ```

## Features

### User Management

#### Creating a User
```
./target/release/bank-account-rust user create --username <username> [--role <role>]
```
- `<username>`: Desired username
- `<role>`: Optional role (default: 'user', alternative: 'admin')

#### Changing Password
```
./target/release/bank-account-rust user change-password
```

#### Enabling Two-Factor Authentication
```
./target/release/bank-account-rust security enable-2fa
```

### Account Management

#### Creating an Account
```
./target/release/bank-account-rust account create --type <account-type>
```
- `<account-type>`: Either 'checking' or 'savings'

#### Viewing Account Details
```
./target/release/bank-account-rust account info --id <account-id>
```

#### Listing Your Accounts
```
./target/release/bank-account-rust account list
```

### Transaction Operations

#### Making a Deposit
```
./target/release/bank-account-rust account deposit --id <account-id> --amount <amount>
```

#### Making a Withdrawal
```
./target/release/bank-account-rust account withdraw --id <account-id> --amount <amount>
```

#### Making a Transfer
```
./target/release/bank-account-rust account transfer --from <from-account-id> --to <to-account-id> --amount <amount>
```

#### Viewing Transaction History
```
./target/release/bank-account-rust account history --id <account-id> [--from <date>] [--to <date>]
```

### Security Features

#### Two-Factor Authentication
```
# Enable 2FA
./target/release/bank-account-rust security enable-2fa

# Disable 2FA
./target/release/bank-account-rust security disable-2fa
```

#### Account Locking
After five failed login attempts, an account will be automatically locked. An admin must unlock it:
```
./target/release/bank-account-rust user unlock --username <username>
```

## Security Guidelines

### Password Management

1. **Create Strong Passwords**:
   - Use at least 12 characters
   - Include uppercase and lowercase letters, numbers, and special characters
   - Avoid dictionary words and common patterns
   - Don't reuse passwords from other services

2. **Regular Password Changes**:
   - Change your password every 90 days
   - Don't reuse previously used passwords

3. **Secure Password Handling**:
   - Never share your password with anyone
   - Don't write down your password
   - Don't store passwords in plain text files

### Access Protection

1. **Enable Two-Factor Authentication**:
   - Always use 2FA for enhanced account security
   - Keep backup codes in a secure location
   - Use a dedicated authenticator app (like Google Authenticator or Authy)

2. **Session Management**:
   - Always log out when you're done using the application
   - Don't leave your terminal unattended while logged in
   - Sessions will automatically expire after 30 minutes of inactivity

3. **Physical Security**:
   - Ensure your computer is secured with a password
   - Don't use the banking application on public computers
   - Keep your authenticator device (phone) secure

### Data Protection

1. **Sensitive Information**:
   - Don't include sensitive personal information in transaction descriptions
   - Review account statements regularly for unauthorized transactions

2. **Database Security**:
   - The application database is encrypted at rest
   - Backup files are also encrypted
   - Ensure your system has proper access controls to protect data files

3. **Transaction Verification**:
   - Always verify transaction details before confirming
   - Report any suspicious activity immediately

### Secure Environment

1. **System Updates**:
   - Keep your operating system and software up to date
   - Use antivirus software and keep it updated

2. **Network Security**:
   - Use trusted networks for banking operations
   - Consider using a VPN for additional security

## Troubleshooting

### Common Issues

#### Authentication Problems
- **Issue**: Unable to log in despite correct credentials
  **Solution**: After five failed attempts, your account may be locked. Contact an administrator to unlock it.

- **Issue**: 2FA is not accepting your code
  **Solution**: Ensure your system clock is accurate. Time drift can cause 2FA codes to be rejected.

#### Transaction Issues
- **Issue**: Transaction fails with "Insufficient funds"
  **Solution**: Check your account balance and ensure you have enough funds including any transaction fees.

- **Issue**: "Transaction limit exceeded" error
  **Solution**: There are daily limits on transactions. Try a smaller amount or contact an administrator.

#### System Issues
- **Issue**: Application won't start
  **Solution**: Check your `.env` configuration and ensure the database path is correct.

## FAQs

**Q: How do I reset my password if I forget it?**
A: An administrator can reset your password using `user reset-password --username <your-username>`.

**Q: Is my data encrypted?**
A: Yes, all sensitive data is encrypted using AES-256 encryption, and the database is encrypted at rest.

**Q: What happens if I lose my device with 2FA?**
A: You can use the backup codes provided when you set up 2FA. If you don't have these, an administrator can disable 2FA for your account.

**Q: How can I export my transaction history?**
A: Use `account export --id <account-id> --format csv --output <filename>`.

**Q: How long are transaction records kept?**
A: Transaction records are kept for 7 years in accordance with standard financial record-keeping practices.

**Q: Can I schedule recurring transactions?**
A: Yes, use `account schedule-transfer` to set up recurring transfers. 