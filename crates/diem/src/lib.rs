// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod account;
pub mod common;
pub mod config;
pub mod genesis;
pub mod key;
pub mod move_tool;
pub mod node;
pub mod client_proxy;
pub mod diem_client;

use diem_types::account_address::AccountAddress;
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    traits::ValidCryptoMaterialStringExt,
};

use crate::common::types::{CliResult, CliTypedResult};
use clap::Parser;
use serde::{Serialize, Deserialize};

// use std::collections::BTreeMap;

// Command Line Interface (CLI) for developing and interacting with the Diem blockchain
#[derive(Parser)]
#[clap(name = "diem", author, version, propagate_version = true)]
pub enum Tool {
    #[clap(subcommand)]
    Account(account::AccountTool),
    // #[clap(subcommand)]
    // Config(config::ConfigTool),
    // #[clap(subcommand)]
    // Genesis(genesis::GenesisTool),
    // Info(InfoTool),
    // Init(common::init::InitTool),
    // #[clap(subcommand)]
    // Key(key::KeyTool),
    // #[clap(subcommand)]
    // Move(move_tool::MoveTool),
    // #[clap(subcommand)]
    // Node(node::NodeTool),
}

impl Tool {
    pub async fn execute(self) -> Result<String, String> {
        use Tool::*;
        match self {
            Account(tool) => tool.execute().await,
            // Config(tool) => tool.execute().await,
            // Genesis(tool) => tool.execute().await,
            // Info(tool) => tool.execute_serialized().await,
            // Init(tool) => tool.execute_serialized_success().await,
            // Key(tool) => tool.execute().await,
            // Move(tool) => tool.execute().await,
            // Node(tool) => tool.execute().await,
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
