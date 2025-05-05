// Account management module
// This module provides functionality for account creation, management,
// and transaction processing.

mod transactions;
mod management;

pub use transactions::{
    process_transaction,
    transfer_funds,
    TransactionError
}; 

pub use management::{
    create_account,
    get_account,
    get_user_accounts,
    update_account_status,
    calculate_interest,
    link_accounts,
    AccountError
}; 