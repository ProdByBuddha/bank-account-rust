// Account management module
// This module provides functionality for account creation, management,
// and transaction processing.

mod transactions;
mod management;

pub use transactions::{
    process_transaction,
    transfer_funds,
    TransactionError,
    get_transaction_history,
    generate_receipt_for_transaction,
    schedule_transaction,
    create_recurring_transaction,
    process_scheduled_transactions,
    cancel_scheduled_transaction,
    cancel_recurring_transaction,
    encrypt_transaction_details,
    decrypt_transaction_details,
    RecurrenceFrequency
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