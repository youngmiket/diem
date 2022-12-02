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



use crate::common::types::{CliResult, CliTypedResult};
use clap::Parser;

// use std::collections::BTreeMap;

// Command Line Interface (CLI) for developing and interacting with the Diem blockchain
#[derive(Parser)]
#[clap(name = "diem", author, version, propagate_version = true)]
pub enum Tool {
    #[clap(subcommand)]
    Account(account::AccountTool),

}

impl Tool {
    pub async fn execute(self) -> Result<String, String> {
        use Tool::*;
        match self {
            Account(tool) => tool.execute().await,

        }
    }
}

