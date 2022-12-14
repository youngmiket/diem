// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::common::types::{CliError, Command};

use crate::{client_proxy::ClientProxy, client_proxy::default_proxy};

use async_trait::async_trait;
use clap::Parser;

use diem_types::{transaction::{authenticator::AuthenticationKey}};

/// Mint coins to an account
///
/// This mints coins to an account.
/// If the account does not exist on chain it will be created.
#[derive(Debug, Parser)]
pub struct MintAccount {
    account: String,
    amount: u64,
    currency: String
}

#[async_trait]
impl Command<String> for MintAccount {
    fn command_name(&self) -> &'static str {
        "MintAccount"
    }

    async fn execute(self) -> Result<String, CliError> {
        //find account to mint to
        //currency
        //amount
        //check which chain
        //if testnet, faucet can create account
        //if not, tc account needs to create account

        //questions
        //should we have a max mint?
        //what currencies?

        //default for testing
        let mut client = default_proxy().await;

        //verify authentication key
        let (receiver, receiver_auth_key_opt) =
            client.get_account_address_from_parameter(&self.account).unwrap();
        let receiver_auth_key = receiver_auth_key_opt.ok_or_else(|| {
            println!("Need authentication key to create new account via minting from facuet")
        }).unwrap();

        client.mint_coins_with_faucet_service(receiver_auth_key, self.amount, self.currency).await;
        
        Ok("Minted coins successfully".to_string())
    }
}
