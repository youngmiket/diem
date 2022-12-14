// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0



use crate::account::{
    AccountData, AccountStatus
};
use diem_types::{
    chain_id::ChainId, ledger_info::LedgerInfo, on_chain_config::ValidatorSet,
    waypoint::Waypoint,
};
use anyhow::{bail, ensure, format_err, Error};

use crate::{
    diem_client::DiemClient,
    
};
use structopt::StructOpt;

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
    time
};
use serde::{Serialize, Deserialize};
use rand::{prelude::StdRng, SeedableRng};

use swiss_knife::helpers;

const CLIENT_WALLET_MNEMONIC_FILE: &str = "client.mnemonic";
const DEFAULT_WAIT_TIMEOUT: time::Duration = time::Duration::from_secs(120);

/// Enum used for error formatting.
#[derive(Debug)]
enum InputType {
    Bool,
    UnsignedInt,
    Usize,
}

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

    pub async fn mint_coins_with_faucet_service(
        &mut self,
        receiver: AuthenticationKey,
        num_coins: u64,
        coin_currency: String,
    ) -> Result<()> {
        let client = reqwest::ClientBuilder::new().build()?;

        let url = Url::parse_with_params(
            self.faucet_url.as_str(),
            &[
                ("amount", num_coins.to_string().as_str()),
                ("auth_key", &hex::encode(receiver)),
                ("currency_code", coin_currency.as_str()),
                ("return_txns", "true"),
            ],
        )?;

        let response = client.post(url).send().await?;
        let status_code = response.status();
        let body = response.text().await?;
        if !status_code.is_success() {
            return Err(format_err!(
                "Failed to query remote faucet server[status={}]: {:?}",
                status_code.as_str(),
                body,
            ));
        }
        let bytes = hex::decode(body)?;
        let txns: Vec<SignedTransaction> = bcs::from_bytes(&bytes).unwrap();
        for txn in &txns {
            self.wait_for_signed_transaction(txn).await.map_err(|e| {
                info!("minting transaction error: {}", e);
                format_err!("transaction execution failed, please retry")
            })?;
        }

        Ok(())
    }

    /// Waits for the transaction
    pub async fn wait_for_signed_transaction(
        &mut self,
        txn: &SignedTransaction,
    ) -> Result<views::TransactionView> {
        let (tx, rx) = std::sync::mpsc::channel();
        if !self.quiet_wait {
            let _handler = std::thread::spawn(move || loop {
                if rx.try_recv().is_ok() {
                    break;
                }
                print!(".");
                stdout().flush().unwrap();
                std::thread::sleep(time::Duration::from_millis(10));
            });
        }

        let ret = self.client.wait_for_transaction(txn, DEFAULT_WAIT_TIMEOUT).await;
        let ac_update = self.get_account_and_update(&txn.sender()).await;

        if !self.quiet_wait {
            tx.send(()).expect("stop waiting thread");
            println!();
        }

        if let Err(err) = ac_update {
            println!("account update failed: {}", err);
        }
        match ret {
            Ok(t) => Ok(t),
            Err(WaitForTransactionError::TransactionExecutionFailed(txn)) => Err(format_err!(
                "transaction failed to execute; status: {:?}!",
                txn.vm_status
            )),
            Err(e) => Err(anyhow::Error::new(e)),
        }
    }
    /// Wait for transaction, this function is not safe for waiting for a specific transaction,
    /// should use wait_for_signed_transaction instead.
    /// TODO: rename to wait_for_account_seq or remove
    pub async fn wait_for_transaction(&self, address: AccountAddress, seq: u64) -> Result<()> {
        let start = time::Instant::now();
        while start.elapsed() < DEFAULT_WAIT_TIMEOUT {
            let account_txn = self.client.get_txn_by_acc_seq(&address, seq, false).await.unwrap();
            if let Some(txn) = account_txn {
                if let views::TransactionDataView::UserTransaction {
                    sequence_number, ..
                } = txn.transaction
                {
                    if sequence_number >= seq {
                        return Ok(());
                    }
                }
            }
            std::thread::sleep(time::Duration::from_millis(10));
        }
        bail!(
            "wait for account(address={}) transaction(seq={}) timeout",
            address,
            seq
        )
    }

    /// Get account from validator and update status of account if it is cached locally.
    async fn get_account_and_update(
        &mut self,
        address: &AccountAddress,
    ) -> Result<Option<views::AccountView>> {
        let account = self.client.get_account(address).await.unwrap();
        // This isn't used by anything except to keep track of the current version and to simulate
        // some potential verifiable clients, which is yet to be implemented. It also has some
        // challenges in handling retries if the upstream hasn't yet arrived at the expected
        // version and breaks with our testnet deployment, so disabling this for now.
        // self.client.update_and_verify_state_proof()?;

        if let Some(ac) = account.as_ref() {
            self.update_account_seq(address, ac.sequence_number)
        }
        Ok(account)
    }

    /// Update account seq
    fn update_account_seq(&mut self, address: &AccountAddress, seq: u64) {
        if let Some(diem_root_account) = &mut self.diem_root_account {
            if &diem_root_account.address == address {
                diem_root_account.sequence_number = seq;
            }
        }
        if let Some(tc_account) = &mut self.tc_account {
            if &tc_account.address == address {
                tc_account.sequence_number = seq;
            }
        }
        if let Some(testnet_dd_account) = &mut self.testnet_designated_dealer_account {
            if &testnet_dd_account.address == address {
                testnet_dd_account.sequence_number = seq;
            }
        }
        if let Ok((ref_id, _)) = self.get_account_data_and_id(address) {
            // assumption follows from invariant
            let mut account_data: &mut AccountData = self.accounts.get_mut(ref_id).unwrap();
            account_data.status = AccountStatus::Persisted;
            account_data.sequence_number = seq;
        };
    }
    fn get_account_data_and_id(&self, address: &AccountAddress) -> Result<(usize, &AccountData)> {
        for (index, acc) in self.accounts.iter().enumerate() {
            if &acc.address == address {
                return Ok((index, acc));
            }
        }
        bail!(
            "Unable to find existing managing account by address: {}, to see all existing \
                     accounts, run: 'account list'",
            address
        )
    }
    /// Get account address and (if applicable) authentication key from parameter. If the parameter
    /// is string of address, try to convert it to address, otherwise, try to convert to u64 and
    /// looking at TestClient::accounts.
    pub fn get_account_address_from_parameter(
        &self,
        para: &str,
    ) -> Result<(AccountAddress, Option<AuthenticationKey>)> {
        if is_authentication_key(para) {
            let auth_key = ClientProxy::authentication_key_from_string(para)?;
            Ok((auth_key.derived_address(), Some(auth_key)))
        } else if is_address(para) {
            Ok((ClientProxy::address_from_strings(para)?, None))
        } else {
            let account_ref_id = para.parse::<usize>().map_err(|error| {
                format_parse_data_error(
                    "account_reference_id/account_address",
                    InputType::Usize,
                    para,
                    error,
                )
            })?;
            let account_data = self.accounts.get(account_ref_id).ok_or_else(|| {
                format_err!(
                    "Unable to find account by account reference id: {}, to see all existing \
                     accounts, run: 'account list'",
                    account_ref_id
                )
            })?;
            Ok((
                account_data.address,
                account_data
                    .authentication_key
                    .clone()
                    .and_then(|bytes| AuthenticationKey::try_from(bytes).ok()),
            ))
        }
    }
    fn authentication_key_from_string(data: &str) -> Result<AuthenticationKey> {
        let bytes_vec: Vec<u8> = hex::decode(data.parse::<String>()?)?;
        ensure!(
            bytes_vec.len() == AuthenticationKey::LENGTH,
            "The authentication key string {:?} is of invalid length. Authentication keys must be 32-bytes long"
        );

        let auth_key = AuthenticationKey::try_from(&bytes_vec[..]).map_err(|error| {
            format_err!(
                "The authentication key {:?} is invalid, error: {:?}",
                &bytes_vec,
                error,
            )
        })?;
        Ok(auth_key)
    }
    fn address_from_strings(data: &str) -> Result<AccountAddress> {
        let account_vec: Vec<u8> = hex::decode(data.parse::<String>()?)?;
        ensure!(
            account_vec.len() == AccountAddress::LENGTH,
            "The address {:?} is of invalid length. Addresses must be 16-bytes long"
        );
        let account = AccountAddress::try_from(&account_vec[..]).map_err(|error| {
            format_err!(
                "The address {:?} is invalid, error: {:?}",
                &account_vec,
                error,
            )
        })?;
        Ok(account)
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

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Diem Client",
    author = "The Diem Association",
    about = "Diem client to connect to a specific validator"
)]
pub struct DefaultArgs {
    /// Chain ID of the network this client is connecting to
    #[structopt(
        short = "c",
        long,
        help = "\
            Explicitly specify the chain ID of the network the CLI is connecting to: e.g.,
            for mainnet: \"MAINNET\" or 1, testnet: \"TESTNET\" or 2, devnet: \"DEVNET\" or 3, \
            local swarm: \"TESTING\" or 4
            Note: Chain ID of 0 is not allowed
        "
    )]
    pub chain_id: ChainId,
    /// Full URL address to connect to - should include port number, if applicable
    #[structopt(short = "u", long)]
    pub url: String,
    /// Path to the generated keypair for the faucet account. The faucet account can be used to
    /// mint coins. If not passed, a new keypair will be generated for
    /// you and placed in a temporary directory.
    /// To manually generate a keypair, use generate-key:
    /// `cargo run -p generate-keypair -- -o <output_file_path>`
    #[structopt(short = "m", long = "faucet-key-file-path")]
    pub faucet_account_file: Option<String>,
    /// Host that operates a faucet service
    /// If not passed, will be derived from host parameter
    #[structopt(short = "f", long)]
    pub faucet_url: Option<String>,
    /// File location from which to load mnemonic word for user account address/key generation.
    /// If not passed, a new mnemonic file will be generated by diem-wallet in the current
    /// directory.
    #[structopt(short = "n", long)]
    pub mnemonic_file: Option<String>,
    /// If set, client will sync with validator during wallet recovery.
    #[structopt(short = "r", long = "sync")]
    pub sync: bool,
    /// If set, a client uses the waypoint parameter for its initial LedgerInfo verification.
    #[structopt(
        name = "waypoint",
        long,
        help = "Explicitly specify the waypoint to use",
        required_unless = "waypoint_url"
    )]
    pub waypoint: Option<Waypoint>,
    #[structopt(
        name = "waypoint_url",
        long,
        help = "URL for a file with the waypoint to use",
        required_unless = "waypoint"
    )]
    pub waypoint_url: Option<String>,
    /// Verbose output.
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
}

impl DefaultArgs {
    //temporary default arguments for development
    pub fn new() -> Self {
        let testnet = String::from("TESTNET");
        let chain_id = ChainId::from_str(&testnet).unwrap();

        DefaultArgs { chain_id: chain_id, url: String::from("https://testnet.diem.com/v1"), faucet_account_file: None, faucet_url: None, mnemonic_file: None, sync: false, waypoint: None, waypoint_url: Some(String::from("https://testnet.diem.com/waypoint.txt")), verbose: true }
    }

    
}

pub async fn default_proxy() -> ClientProxy {

    //default for testing
    let args = DefaultArgs::new();
    
    
    let faucet_account_file = args
        .faucet_account_file
        .clone()
        .unwrap_or_else(|| "".to_string());
    // Faucet, TreasuryCompliance and DD use the same keypair for now
    let treasury_compliance_account_file = faucet_account_file.clone();
    let dd_account_file = faucet_account_file.clone();
    let mnemonic_file = args.mnemonic_file.clone();

    // let waypoint = args.waypoint.unwrap_or_else(|| async {
    //     args.waypoint_url
    //         .as_ref()
    //         .map(|url_str| async{
    //             retrieve_waypoint(url_str.as_str()).await.unwrap_or_else(|e| {
    //                 panic!("Failure to retrieve a waypoint from {}: {}", url_str, e)
    //             })
    //         })
    //         .unwrap()
    // });

    //default for testing
    let waypoint = retrieve_waypoint("https://testnet.diem.com/waypoint.txt").await.unwrap();


    let mut client_proxy = ClientProxy::new(
        args.chain_id,
        &args.url,
        &faucet_account_file,
        &treasury_compliance_account_file,
        &dd_account_file,
        args.sync,
        args.faucet_url.clone(),
        mnemonic_file,
        waypoint,
        false,
    ).await
    .expect("Failed to construct client.");
    
    client_proxy
}

/// Retrieve a waypoint given the URL.
async fn retrieve_waypoint(url_str: &str) -> anyhow::Result<Waypoint> {
    let client = reqwest::ClientBuilder::new().build()?;
    let response = client.get(url_str).send().await?;

    response
        .error_for_status()
        .map_err(|_| anyhow::format_err!("Failed to retrieve waypoint from URL {}", url_str))?
        .text().await
        .map(|r| Waypoint::from_str(r.trim()))?
}

/// Check whether the input string is a valid diem authentication key.
pub fn is_authentication_key(data: &str) -> bool {
    hex::decode(data).map_or(false, |vec| vec.len() == AuthenticationKey::LENGTH)
}

/// Check whether the input string is a valid diem address.
pub fn is_address(data: &str) -> bool {
    hex::decode(data).map_or(false, |vec| vec.len() == AccountAddress::LENGTH)
}

fn format_parse_data_error<T: std::fmt::Debug>(
    field: &str,
    input_type: InputType,
    value: &str,
    error: T,
) -> Error {
    format_err!(
        "Unable to parse input for {} - \
         please enter an {:?}.  Input was: {}, error: {:?}",
        field,
        input_type,
        value,
        error
    )
}