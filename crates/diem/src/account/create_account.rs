// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0



use crate::common::types:: {
    CliCommand,CliError, CliTypedResult
};

use crate::{
    client_proxy::ClientProxy, client_proxy::GenerateKeypairResponse, client_proxy::generate_key_pair, client_proxy::DefaultArgs, client_proxy::default_proxy
};


use async_trait::async_trait;
use clap::{Parser};
use serde_json::json;
use std::fmt::format;
use std::fs;
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
    fs::File,
};



/// Create a new local account
///
/// An account can be created by transferring coins, or by making an explicit
/// call to create an account.  This will create an account with no coins, and
/// any coins will have to transferred afterwards.
#[derive(Debug, Parser)]
pub struct CreateAccount {}

#[async_trait]
impl CliCommand<String> for CreateAccount {
    fn command_name(&self) -> &'static str {
        "CreateAccount"
    }

    async fn execute(self) -> CliTypedResult<String> {

        //Create an account based on the current diem cli code
        // let mut client = default_proxy().await;

        // match client.create_next_account(true).await {
        //     Ok(account_data) => println!(
        //         "Created/retrieved local account #{} address {}",
        //         account_data.index,
        //         hex::encode(account_data.address)
        //     ),
        //     Err(e) => println!("Error creating local account {}", e),
        // }

        let keypair = generate_key_pair(None);

        match save_keypair(keypair) {
            Ok(_) => println!("Keypair saved"),
            Err(err) => println!("Error saving keypair {}", err)
        };

        
        
        Ok("account".to_string())
    }
}

fn save_keypair (keypair: GenerateKeypairResponse ) -> Result<(), serde_json::Error> {
    let serialized = serde_json::to_string_pretty(&keypair).unwrap();
    println!("key_pair: {}", serialized);

    let folder = ".diem/account/".to_string();

    let path = format!("{}{}-keypair.json",&folder, &keypair.diem_account_address);

    if !std::path::Path::new(&folder).exists() {
        match fs::create_dir_all(folder) {
            Ok(()) => {}
            Err(err) => {panic!("Error creating directory to save keypair file: {}", err)}
        };
    } 

    let file = File::create(path).unwrap();

    let res = serde_json::to_writer_pretty(&file, &keypair);
    
    res
}
