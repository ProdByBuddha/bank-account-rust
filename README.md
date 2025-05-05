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

## Development Metrics

This project includes a commit statistics tracking script to help estimate development time and costs.

### Using the Commit Statistics Tracker

```bash
# Log statistics for the most recent commit
./commit_stats.py log --hours 2.5

# Log statistics for a specific commit with custom hourly rate
./commit_stats.py log --commit abc123 --hours 3.0 --rate 175

# Generate a report of all logged commits
./commit_stats.py report
```

The script tracks:
- Time spent per commit
- Code changes (files, insertions, deletions)
- Cost based on hourly rate
- Project totals for time and cost

Data is stored in `commit_statistics.json` for easy analysis.

## Security Considerations

This application implements industry-standard security practices:

- All sensitive data is encrypted using AES-256
- Passwords are hashed using Argon2id
- Authentication uses signed and encrypted JWT tokens
- Account access requires verification for sensitive operations
- All actions are logged in tamper-evident audit trails

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
