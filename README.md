# Secure Banking CLI

A security-focused terminal-based banking system written in Rust. This application implements high-security standards including AES-256 encryption, JWT+JWE authentication, and PCI-DSS compliance checks.

## Features

- **Security-First Approach**: Implements industry-standard security measures.
- **AES-256 Encryption**: All sensitive data is encrypted at rest.
- **JWT+JWE Authentication**: Secure token-based authentication.
- **Role-Based Access Control**: Different privileges for different user types.
- **PCI-DSS Compliance**: Follows payment card industry standards.

## Installation

### Prerequisites

- Rust (latest stable version)
- SQLite

### Building from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/prodbybuddha/bank-account-rust.git
   cd bank-account-rust
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Run the executable:

   ```bash
   ./target/release/bank-account-rust
   ```

## Usage

### First-time Setup

```bash
# Initialize the system and create admin user
bank-account-rust init

# Login as admin
bank-account-rust login --username admin
```

### User Management

```bash
# Create a new user
bank-account-rust user create --username john --role user

# Change password
bank-account-rust user change-password

# Enable 2FA
bank-account-rust user enable-2fa
```

### Account Operations

```bash
# Create a new account
bank-account-rust account create --type checking

# Deposit funds
bank-account-rust account deposit --id ACCOUNT_ID --amount 100.00

# Withdraw funds
bank-account-rust account withdraw --id ACCOUNT_ID --amount 50.00

# Transfer funds
bank-account-rust account transfer --from ACCOUNT_ID --to ACCOUNT_ID --amount 25.00

# View balance
bank-account-rust account balance --id ACCOUNT_ID

# View transaction history
bank-account-rust account history --id ACCOUNT_ID
```

### Security Operations

```bash
# Run PCI-DSS compliance check
bank-account-rust security compliance-check

# Export encrypted backup
bank-account-rust security backup --output backup.enc
```

## Security Considerations

This application implements industry-standard security practices:

- All sensitive data is encrypted using AES-256
- Passwords are hashed using Argon2id
- Authentication uses signed and encrypted JWT tokens
- Account access requires verification for sensitive operations
- All actions are logged in tamper-evident audit trails

## License

This project is licensed under the MIT License - see the LICENSE file for details.
