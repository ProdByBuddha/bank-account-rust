// Account management module
// This module provides functionality for account creation, management,
// and transaction processing.

mod transactions;

pub use transactions::{
    process_transaction,
    transfer_funds,
    TransactionError
}; 