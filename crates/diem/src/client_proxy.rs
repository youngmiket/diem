// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0



use crate::account::{
    AccountData, AccountStatus
};
use diem_types::{
    chain_id::ChainId, ledger_info::LedgerInfo, on_chain_config::ValidatorSet,
    waypoint::Waypoint,
};

use crate::{
    diem_client::DiemClient,
    
};

use anyhow::Result;
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    test_utils::KeyPair, Uniform, ValidCryptoMaterialStringExt,
};
use diem_client::{
    stream::{StreamingClient, StreamingClientConfig},
    views, StreamResult, WaitForTransactionError,
};

use diem_logger::prelude::{error, info};


use diem_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    account_config::{
        diem_root_address, from_currency_code_string, testnet_dd_account_address,
        treasury_compliance_account_address, type_tag_for_currency_code, XDX_NAME, XUS_NAME,
    },
    account_state::AccountState,
    ledger_info::LedgerInfoWithSignatures,
    transaction::{
        authenticator::AuthenticationKey,
        helpers::{create_unsigned_txn, create_user_txn, TransactionSigner},
        parse_transaction_argument, ChangeSet, Module, RawTransaction, Script, SignedTransaction,
        TransactionArgument, TransactionPayload, Version, WriteSetPayload,
    },
    write_set::{WriteOp, WriteSetMut},
};
use reqwest::Url;
use diem_wallet::{io_utils, WalletLibrary};


use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt, fs,
    io::{stdout, Write},
    path::{Path, PathBuf},
    process::Command,
    str::{self, FromStr},
};
use serde::{Serialize, Deserialize};
use rand::{prelude::StdRng, SeedableRng};

use swiss_knife::helpers;

const CLIENT_WALLET_MNEMONIC_FILE: &str = "client.mnemonic";



/// Account data is stored in a map and referenced by an index.
#[derive(Debug)]
pub struct AddressAndIndex {
    /// Address of the account.
    pub address: AccountAddress,
    /// The account_ref_id of this account in client.
    pub index: usize,
}

/// Proxy handling CLI commands/inputs.
pub struct ClientProxy {
    /// chain ID of the Diem network this client is interacting with
    pub chain_id: ChainId,
    /// client for admission control interface.
    pub client: DiemClient,
    /// Created accounts.
    pub accounts: Vec<AccountData>,
    /// Address to account_ref_id map.
    address_to_ref_id: HashMap<AccountAddress, usize>,
    /// Host that operates a faucet service
    faucet_url: Url,
    /// Account used for Diem Root operations (e.g., adding a new transaction script)
    pub diem_root_account: Option<AccountData>,
    /// Account used for Treasury Compliance operations
    pub tc_account: Option<AccountData>,
    /// Account used for "minting" operations
    pub testnet_designated_dealer_account: Option<AccountData>,
    /// do not print '.' when waiting for signed transaction
    pub quiet_wait: bool,
    /// Wallet library managing user accounts.
    pub wallet: WalletLibrary,
    /// Whether to sync with validator on wallet recovery.
    sync_on_wallet_recovery: bool,
    /// temp files (alive for duration of program)
    temp_files: Vec<PathBuf>,
    /// Host of the node that client connects to
    pub url: Url,
}

impl ClientProxy {
    /// Construct a new TestClient.
    pub async fn new(
        chain_id: ChainId,
        url: &str,
        diem_root_account_file: &str,
        tc_account_file: &str,
        testnet_designated_dealer_account_file: &str,
        sync_on_wallet_recovery: bool,
        faucet_url: Option<String>,
        mnemonic_file: Option<String>,
        waypoint: Waypoint,
        quiet_wait: bool,
    ) -> Result<Self> {
        // fail fast if url is not valid
        let url = Url::parse(url)?;
        let client = DiemClient::new(url.clone(), waypoint)?;

        let accounts = vec![];

        let diem_root_account = if diem_root_account_file.is_empty() {
            None
        } else {
            let diem_root_account_key = generate_key::load_key(diem_root_account_file);
            let diem_root_account_data = Self::get_account_data_from_address(
                &client,
                diem_root_address(),
                true,
                Some(KeyPair::from(diem_root_account_key)),
                None,
            ).await?;
            Some(diem_root_account_data)
        };

        let tc_account = if tc_account_file.is_empty() {
            None
        } else {
            let tc_account_key = generate_key::load_key(tc_account_file);
            let tc_account_data = Self::get_account_data_from_address(
                &client,
                treasury_compliance_account_address(),
                true,
                Some(KeyPair::from(tc_account_key)),
                None,
            ).await?;
            Some(tc_account_data)
        };

        let dd_account = if testnet_designated_dealer_account_file.is_empty() {
            None
        } else {
            let dd_account_key = generate_key::load_key(testnet_designated_dealer_account_file);
            let dd_account_data = Self::get_account_data_from_address(
                &client,
                testnet_dd_account_address(),
                true,
                Some(KeyPair::from(dd_account_key)),
                None,
            ).await?;
            Some(dd_account_data)
        };

        let faucet_url = if let Some(faucet_url) = &faucet_url {
            Url::parse(faucet_url).expect("Invalid faucet URL specified")
        } else {
            url.join("/mint")
                .expect("Failed to construct faucet URL from JSON-RPC URL")
        };

        let address_to_ref_id = accounts
            .iter()
            .enumerate()
            .map(|(ref_id, acc_data): (usize, &AccountData)| (acc_data.address, ref_id))
            .collect::<HashMap<AccountAddress, usize>>();

        Ok(ClientProxy {
            chain_id,
            client,
            accounts,
            address_to_ref_id,
            faucet_url,
            diem_root_account,
            tc_account,
            testnet_designated_dealer_account: dd_account,
            wallet: Self::get_diem_wallet(mnemonic_file)?,
            sync_on_wallet_recovery,
            temp_files: vec![],
            quiet_wait,
            url,
        })
    }

    /// Returns the account index that should be used by user to reference this account
    pub async fn create_next_account(&mut self, sync_with_validator: bool) -> Result<AddressAndIndex> {
        let (auth_key, _) = self.wallet.new_address()?;
        let account_data = Self::get_account_data_from_address(
            &self.client,
            auth_key.derived_address(),
            sync_with_validator,
            None,
            Some(auth_key.to_vec()),
        ).await?;

        Ok(self.insert_account_data(account_data))
    }

    /// Get account using specific address.
    /// Sync with validator for account sequence number in case it is already created on chain.
    /// This assumes we have a very low probability of mnemonic word conflict.
    #[allow(clippy::unnecessary_wraps)]
    async fn get_account_data_from_address(
        client: &DiemClient,
        address: AccountAddress,
        sync_with_validator: bool,
        key_pair: Option<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        authentication_key_opt: Option<Vec<u8>>,
    ) -> Result<AccountData> {
        let (sequence_number, authentication_key, status) = if sync_with_validator {
            let ret = client.get_account(&address).await;
            match ret {
                Ok(resp) => match resp {
                    Some(account_view) => (
                        account_view.sequence_number,
                        Some(account_view.authentication_key.into_inner().into()),
                        AccountStatus::Persisted,
                    ),
                    None => (0, authentication_key_opt, AccountStatus::Local),
                },
                Err(e) => {
                    error!("Failed to get account from validator, error: {:?}", e);
                    (0, authentication_key_opt, AccountStatus::Unknown)
                }
            }
        } else {
            (0, authentication_key_opt, AccountStatus::Local)
        };
        Ok(AccountData {
            address,
            authentication_key,
            key_pair,
            sequence_number,
            status,
        })
    }

    fn get_diem_wallet(mnemonic_file: Option<String>) -> Result<WalletLibrary> {
        let wallet_recovery_file_path = if let Some(input_mnemonic_word) = mnemonic_file {
            Path::new(&input_mnemonic_word).to_path_buf()
        } else {
            let mut file_path = std::env::current_dir()?;
            file_path.push(CLIENT_WALLET_MNEMONIC_FILE);
            file_path
        };

        let wallet = if let Ok(recovered_wallet) = io_utils::recover(&wallet_recovery_file_path) {
            recovered_wallet
        } else {
            let new_wallet = WalletLibrary::new();
            new_wallet.write_recovery(&wallet_recovery_file_path)?;
            new_wallet
        };
        Ok(wallet)
    }
    /// Insert the account data to Client::accounts and return its address and index.s
    pub fn insert_account_data(&mut self, account_data: AccountData) -> AddressAndIndex {
        let address = account_data.address;

        self.accounts.push(account_data);
        self.address_to_ref_id
            .insert(address, self.accounts.len() - 1);

        AddressAndIndex {
            address,
            index: self.accounts.len() - 1,
        }
    }

    
}



//moved from swiss knife
#[derive(Deserialize, Serialize)]
// #[serde(rename_all = "snake_case")]
pub struct GenerateKeypairResponse {
    pub private_key: String,
    pub public_key: String,
    pub diem_auth_key: String,
    pub diem_account_address: String,
}

pub fn generate_key_pair(seed: Option<u64>) -> GenerateKeypairResponse {
    let mut rng = StdRng::seed_from_u64(seed.unwrap_or_else(rand::random));
    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = Ed25519PrivateKey::generate(&mut rng).into();
        
    let diem_auth_key = AuthenticationKey::ed25519(&keypair.public_key);
    let diem_account_address: String = diem_auth_key.derived_address().to_string();
    let diem_auth_key: String = diem_auth_key.to_string();
    GenerateKeypairResponse {
        private_key: keypair
            .private_key.to_encoded_string()
            .map_err(|err| {
                helpers::exit_with_error(format!("Failed to encode private key : {}", err))
            })
            .unwrap(),
        public_key: keypair
            .public_key
            .to_encoded_string()
            .map_err(|err| {
                helpers::exit_with_error(format!("Failed to encode public key : {}", err))
            })
            .unwrap(),
        diem_auth_key,
        diem_account_address,
    }
}

