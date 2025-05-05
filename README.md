# Secure Banking CLI

A security-focused terminal-based banking system written in Rust. This application implements high-security standards including AES-256 encryption, JWT+JWE authentication, and PCI-DSS compliance checks.

## Features

- AES-256 encryption for all sensitive data
- JWT+JWE (JOSE) authentication flow
- Role-based access control (admin/user)
- Secure SQLite database with encryption
- Append-only audit trails for compliance
- Two-factor authentication
- PCI-DSS compliance checks

## Installation

### Prerequisites

- Rust (latest stable version)
- SQLite

### Building from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/prodbybuddha/secure-bank-cli.git
   cd secure-bank-cli
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Run the executable:

   ```bash
   ./target/release/secure-bank-cli
   ```

## Usage

### First-time Setup

```bash
# Initialize the system and create admin user
secure-bank-cli init

# Login as admin
secure-bank-cli login --username admin
```

### User Management

```bash
# Create a new user
secure-bank-cli user create --username john --role user

# Change password
secure-bank-cli user change-password

# Enable 2FA
secure-bank-cli user enable-2fa
```

### Account Operations

```bash
# Create a new account
secure-bank-cli account create --type checking

# Deposit funds
secure-bank-cli account deposit --id ACCOUNT_ID --amount 100.00

# Withdraw funds
secure-bank-cli account withdraw --id ACCOUNT_ID --amount 50.00

# Transfer funds
secure-bank-cli account transfer --from ACCOUNT_ID --to ACCOUNT_ID --amount 25.00

# View balance
secure-bank-cli account balance --id ACCOUNT_ID

# View transaction history
secure-bank-cli account history --id ACCOUNT_ID
```

### Security Operations

```bash
# Run PCI-DSS compliance check
secure-bank-cli security compliance-check

# Export encrypted backup
secure-bank-cli security backup --output backup.enc
```

## Security Considerations

This application implements industry-standard security practices:

- All sensitive data is encrypted using AES-256
- Passwords are hashed using Argon2id
- Authentication uses signed and encrypted JWT tokens
- Account access requires verification for sensitive operations
- All actions are logged in tamper-evident audit trails

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
