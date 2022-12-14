// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common::types::Command;
use clap::Subcommand;

pub mod create_account;
pub mod mint;

use serde::{Serialize, Deserialize};
use diem_types::account_address::AccountAddress;
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    traits::ValidCryptoMaterialStringExt,
};


/// Tool to interact with account data
///
/// This is used to create, request information and facilitate transfers between accounts.
#[derive(Debug, Subcommand)]
pub enum AccountSubcommand {
    Create(create_account::CreateAccount),
    Mint(mint::MintAccount)
}

impl AccountSubcommand {
    pub async fn execute(self) -> Result<String, String> {
        match self {
            AccountSubcommand::Create(tool) => tool.execute_serialized().await,
            AccountSubcommand::Mint(tool) => tool.execute_serialized().await,
        }
    }
}

/// Struct used to store data for each created account.  We track the sequence number
/// so we can create new transactions easily
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Clone))]
pub struct AccountData {
    /// Address of the account.
    pub address: AccountAddress,
    /// Authentication key of the account.
    pub authentication_key: Option<Vec<u8>>,
    /// (private_key, public_key) pair if the account is not managed by wallet.
    pub key_pair: Option<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    /// Latest sequence number maintained by client, it can be different from validator.
    pub sequence_number: u64,
    /// Whether the account is initialized on chain, cached local only, or status unknown.
    pub status: AccountStatus,
}

/// Enum used to represent account status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountStatus {
    /// Account exists only in local cache, it is not persisted on chain.
    Local,
    /// Account is persisted on chain.
    Persisted,
    /// Not able to check account status, probably because client is not able to talk to the
    /// validator.
    Unknown,
}
