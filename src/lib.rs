#![deny(
    bad_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    private_in_public,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    missing_debug_implementations,
    unsafe_code
)]

//! A library for fEVM related utililty functions in rust
//!
//!

/// FVM and fEVM local executors (for testing purposes)
pub mod executor;

pub mod multisig_utils;

use ::ethers::contract::Contract;
use async_recursion::async_recursion;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::prelude::HDPath::LedgerLive;
use ethers::prelude::Ledger;
use ethers::signers::Signer;
use ethers::signers::{coins_bip39::English, MnemonicBuilder};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{TransactionReceipt, H256, U256};
use ethers::{
    prelude::{Middleware, SignerMiddleware},
    providers::{Http, Provider},
    signers::Wallet,
};
use leb128 as leb;
use log::{debug, info};
use serde::Deserialize;
use serde_json::{json, ser};
use std::error::Error;
use std::fmt::Write;
use std::fs;
use std::sync::Arc;

const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";

/// A multiplier for gas limits on transactions to circumvent
/// pending transactions on gas spikes.
pub const GAS_LIMIT_MULTIPLIER: u64 = 150;

// The hash length used for calculating address checksums.
const CHECKSUM_HASH_LENGTH: usize = 4;

// The maximum length of `int64` as a string.
const MAX_INT64_STRING_LENGTH: usize = 19;

/// The maximum length of a delegated address's sub-address.
const MAX_SUBADDRESS_LEN: usize = 54;

/// The length of an 0x type Ethereum address
const ETH_ADDRESS_LENGTH: usize = 20;

/// Defines the hash length taken over addresses
/// using the Actor and SECP256K1 protocols.
const PAYLOAD_HASH_LENGTH: usize = 20;

/// The length of a BLS public key
const BLS_PUBLIC_KEY_BYTES: usize = 48;

/// Distinguishes between mainnet and testnet addresses
#[derive(PartialEq, Eq, Clone, Debug)]
#[allow(missing_docs)]
pub enum CoinType {
    MAIN,
    TEST,
}

impl CoinType {
    fn possible_values() -> [char; 2] {
        ['f', 't']
    }
}

impl From<char> for CoinType {
    fn from(a: char) -> Self {
        match a {
            'f' => CoinType::MAIN,
            't' => CoinType::TEST,
            _ => panic!(),
        }
    }
}

/// The addressing protocol being used
#[derive(PartialEq, Eq, Clone, Debug)]
#[allow(missing_docs)]
pub enum Protocol {
    ID = 0,
    SECP256K1 = 1,
    ACTOR = 2,
    BLS = 3,
    DELEGATED = 4,
}

impl Protocol {
    fn possible_values() -> [u64; 5] {
        [0, 1, 2, 3, 4]
    }
}

impl From<u64> for Protocol {
    fn from(a: u64) -> Self {
        match a {
            0 => Protocol::ID,
            1 => Protocol::SECP256K1,
            2 => Protocol::ACTOR,
            3 => Protocol::BLS,
            4 => Protocol::DELEGATED,
            _ => panic!(),
        }
    }
}

/// A struct that holds all components within an address. For more information see here: https://spec.filecoin.io/appendix/address/
#[derive(Debug)]
pub struct AddressData {
    /// A protocol indicator byte that identifies the type and version of this address.
    pub protocol: Protocol,
    /// The payload used to uniquely identify the actor according to the protocol.
    pub payload: Vec<u8>,
    /// address bytes
    pub bytes: Vec<u8>,
    /// the address [CoinType]
    pub coin_type: CoinType,
}

#[derive(thiserror::Error, Debug)]
/// Errors related to address parsing
#[allow(missing_docs)]
pub enum AddressError {
    #[error(
        "Address cointype should be one of: {:#?}",
        CoinType::possible_values()
    )]
    InvalidCointype,
    #[error(
        "Address protocol should be one of: {:#?}",
        Protocol::possible_values()
    )]
    InvalidProtocol,
    #[error("invalid address format")]
    InvalidAddress,
    #[error("invalid base32")]
    InvalidBase32,
    #[error("invalid namespace")]
    InvalidNamespace,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("invalid leb128")]
    InvalidLeb128,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("can only convert delegated addresses to ETH")]
    OnlyConvertDelegated,
    #[error("RPC conversion call failed")]
    RPCFailure,
}

#[derive(thiserror::Error, Debug)]
/// Errors related to transaction issuance
#[allow(missing_docs)]
pub enum TxError {
    #[error(
        "did not receive receipt, but check a hyperspace explorer to check if tx was successful (hash: ${0})"
    )]
    NoReceipt(H256),
}

#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
/// Errors related to wallet generation and parsing
pub enum WalletError {
    #[error("Null private key")]
    NullPrivateKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
}

/// Sets gas for a constructed tx
pub fn set_tx_gas(tx: &mut TypedTransaction, gas_estimate: U256, gas_price: U256) {
    let gas_estimate = gas_estimate * GAS_LIMIT_MULTIPLIER / 100;
    tx.set_gas(gas_estimate);
    tx.set_gas_price(gas_price);
}

/// Sends a constructed tx
pub async fn send_tx<S: Middleware + 'static>(
    tx: &TypedTransaction,
    client: S,
    retries: usize,
) -> Result<TransactionReceipt, Box<dyn Error>> {
    let pending_tx = client.send_transaction(tx.clone(), None).await?;

    let hash = pending_tx.tx_hash();
    let receipt = pending_tx.retries(retries).await?;
    if let Some(receipt) = receipt {
        debug!("call receipt: {:#?}", receipt);
        Ok(receipt)
    } else {
        Err(Box::new(TxError::NoReceipt(hash)))
    }
}

/// Derive a [U256] private key from a mnemonic string.
fn derive_key(mnemonic: &str, path: &str, index: u32) -> Result<U256, WalletError> {
    let derivation_path = if path.ends_with('/') {
        format!("{path}{index}")
    } else {
        format!("{path}/{index}")
    };

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path(&derivation_path)
        .map_err(|_| WalletError::InvalidMnemonic)?
        .build()
        .map_err(|_| WalletError::InvalidMnemonic)?;

    info!("wallet address: {:#?}", wallet.address());

    let private_key = U256::from_big_endian(wallet.signer().to_bytes().as_slice());

    Ok(private_key)
}

// Returns an Ethers Wallet used to sign transactions.
fn get_signing_wallet(private_key: U256, chain_id: u64) -> Result<Wallet<SigningKey>, WalletError> {
    if private_key.is_zero() {
        return Err(WalletError::NullPrivateKey);
    }
    let mut bytes: [u8; 32] = [0; 32];
    private_key.to_big_endian(&mut bytes);
    let private_key =
        SigningKey::from_bytes((&bytes).into()).map_err(|_| WalletError::InvalidPrivateKey)?;
    let wallet: Wallet<SigningKey> = private_key.into();

    Ok(wallet.with_chain_id(chain_id))
}

/// get_provider returns a JSON RPC HTTP Provider for the Filecoin Blockchain
pub fn get_provider(rpc_url: &str) -> Result<Provider<Http>, Box<dyn Error>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    debug!("{:#?}", provider);
    Ok(provider)
}

/// Obtains a Ledger hardware wallet backed [SignerMiddleWare] from an provider and a chain id.
/// This middleware can be used for locally signing and broadcasting transactions while the hardware
/// wallet is connected to the machine.
pub async fn get_ledger_signing_provider(
    provider: Provider<Http>,
    chain_id: u64,
) -> Result<SignerMiddleware<Arc<Provider<Http>>, Ledger>, Box<dyn Error>> {
    // Note: Support for signing transactions using the Ledger Filecoin app still hasn't landed yet and is WIP.
    // So, the workaround for now is to use the Ethereum Ledger App for signing Filecoin transactions
    // after funding the corresponding "Ethereum account" on the Filecoin mainnet with funds.
    let ledger = Ledger::new(LedgerLive(0), chain_id).await?;
    let provider = Arc::new(provider);

    Ok(SignerMiddleware::new(provider, ledger))
}
/// Obtains a [SignerMiddleWare] from an RPC url and a mnemonic string.
/// The middleware can be used for locally signing and broadcasting transactions.
pub async fn get_wallet_signing_provider(
    provider: Provider<Http>,
    mnemonic: &str,
) -> Result<SignerMiddleware<Arc<Provider<Http>>, Wallet<SigningKey>>, Box<dyn Error>> {
    let chain_id = provider.get_chainid().await?;
    let private_key = derive_key(mnemonic, DEFAULT_DERIVATION_PATH_PREFIX, 0)?;
    let signing_wallet = get_signing_wallet(private_key, chain_id.as_u64())?;

    let provider = Arc::new(provider);

    Ok(SignerMiddleware::new(provider, signing_wallet))
}

/// Writes an ethers [Contract]'s abi to a file:
///
/// * contract: the Contract
/// * path: the path to write the abi to
pub fn write_abi(
    contract: Contract<SignerMiddleware<Arc<Provider<Http>>, Wallet<SigningKey>>>,
    path: &str,
) -> Result<(), Box<dyn Error>> {
    let abi = contract.abi();
    let string_abi = ser::to_string(abi)?;
    fs::write(path, string_abi).expect("Unable to write file");
    Ok(())
}

fn validate_checksum(bytes: &[u8], checksum_bytes: &[u8]) -> bool {
    // this should never ever fail given the hardcoded value above
    let mut hasher = Blake2bVar::new(CHECKSUM_HASH_LENGTH).unwrap();
    hasher.update(bytes);
    let mut buf = [0u8; CHECKSUM_HASH_LENGTH];
    hasher.finalize_variable(&mut buf).unwrap();
    buf == checksum_bytes
}

#[derive(Deserialize, Debug)]
struct StateLookupIDResp {
    result: String,
}

/// Checks that an input address string is a valid Filecoin address.
/// Returns the parsed address as an [AddressData] struct. The checksums throughout serve as sanity checks.
///
/// ```
///
/// use fevm_utils::check_address_string;
/// use fevm_utils::Protocol;
/// use fevm_utils::CoinType;
///
///
/// let res = check_address_string("t01");
/// assert!(res.is_ok());
/// let res = res.unwrap();
/// assert_eq!(res.coin_type, CoinType::TEST);
/// assert_eq!(res.protocol, Protocol::ID);
///
/// let res = check_address_string("f01");
/// assert!(res.is_ok());
/// let res = res.unwrap();
/// assert_eq!(res.coin_type, CoinType::MAIN);
/// assert_eq!(res.protocol, Protocol::ID);
///
/// let res = check_address_string("t410fkkld55ioe7qg24wvt7fu6pbknb56ht7pt4zamxa");
/// assert!(res.is_ok());
/// let res = res.unwrap();
/// assert_eq!(res.coin_type, CoinType::TEST);
/// assert_eq!(res.protocol, Protocol::DELEGATED);
///
/// // this is a nonsense address and should fail
/// let res = check_address_string("t4aejhfhfhnnnnnn");
/// assert!(!res.is_ok());
///
/// ```
pub fn check_address_string(address: &str) -> Result<AddressData, AddressError> {
    info!("converting {} to ETH equivalent", address);
    let base32_alphabet = base32::Alphabet::RFC4648 { padding: false };
    if address.len() < 3 {
        return Err(AddressError::InvalidAddress);
    }

    let coin_type = address
        .chars()
        .nth(0)
        .ok_or(AddressError::InvalidCointype)?;
    if !CoinType::possible_values().contains(&coin_type) {
        return Err(AddressError::InvalidCointype);
    }

    let protocol = address
        .chars()
        .nth(1)
        .ok_or(AddressError::InvalidProtocol)?;
    // It works because the ASCII (and thus UTF-8) encodings have the Arabic numerals 0-9 ordered in ascending order.
    // You can get the scalar values and subtract them.
    let protocol = protocol as u64 - '0' as u64;
    if !Protocol::possible_values().contains(&protocol) {
        return Err(AddressError::InvalidProtocol);
    }
    let protocol: Protocol = (protocol).into();

    let raw = &address[2..];

    let mut protocol_buf: [u8; 1024] = [0; 1024];
    let protocol_byte_num = {
        let mut writable = &mut protocol_buf[..];
        leb::write::unsigned(&mut writable, protocol.clone() as u64)
            .map_err(|_| AddressError::InvalidLeb128)?
    };
    if protocol_byte_num != 1 {
        return Err(AddressError::InvalidLeb128);
    }
    let protocol_byte = protocol_buf[0..protocol_byte_num].to_vec();

    let addr = match protocol {
        Protocol::ID => {
            if raw.len() > MAX_INT64_STRING_LENGTH {
                return Err(AddressError::InvalidAddress);
            }
            if raw.parse::<u64>().is_err() {
                return Err(AddressError::InvalidAddress);
            }
            let mut buf: [u8; 6] = [0; 6];
            let payload_num_bytes = {
                let mut writable = &mut buf[..];
                leb::write::unsigned(
                    &mut writable,
                    raw.parse::<u64>()
                        .map_err(|_| AddressError::InvalidPayload)?,
                )
                .map_err(|_| AddressError::InvalidLeb128)?
            };
            let payload = buf[..payload_num_bytes].to_vec();

            let bytes = [protocol_byte.as_slice(), payload.as_slice()].concat();

            AddressData {
                protocol,
                payload: buf[..payload_num_bytes].to_vec(),
                bytes,
                coin_type: coin_type.into(),
            }
        }
        Protocol::DELEGATED => {
            let split_index = raw.find('f').ok_or(AddressError::InvalidAddress)?;
            let namespace_str = &raw[..split_index];
            if namespace_str.len() > MAX_INT64_STRING_LENGTH {
                return Err(AddressError::InvalidAddress);
            }
            let sub_addr_cksm_str = &raw[split_index + 1..];
            let sub_addr_cksm_bytes = base32::decode(base32_alphabet, sub_addr_cksm_str)
                .ok_or(AddressError::InvalidBase32)?;
            if sub_addr_cksm_bytes.len() < CHECKSUM_HASH_LENGTH {
                return Err(AddressError::InvalidAddress);
            }
            let sub_addr_bytes =
                &sub_addr_cksm_bytes[..sub_addr_cksm_bytes.len() - CHECKSUM_HASH_LENGTH];
            let checksum_bytes = &sub_addr_cksm_bytes[sub_addr_bytes.len()..];
            if sub_addr_bytes.len() > MAX_SUBADDRESS_LEN {
                return Err(AddressError::InvalidAddress);
            }

            let mut namespace_buf: [u8; 1024] = [0; 1024];
            let namespace_number = namespace_str
                .parse::<u64>()
                .map_err(|_| AddressError::InvalidNamespace)?;
            let namespace_byte_num = {
                let mut writable = &mut namespace_buf[..];
                leb::write::unsigned(&mut writable, namespace_number)
                    .map_err(|_| AddressError::InvalidLeb128)?
            };
            if namespace_byte_num != 1 {
                return Err(AddressError::InvalidLeb128);
            }
            let namespace_byte = namespace_buf[0..namespace_byte_num].to_vec();

            let bytes = [
                protocol_byte.as_slice(),
                namespace_byte.as_slice(),
                sub_addr_bytes,
            ]
            .concat();

            if !validate_checksum(&bytes, checksum_bytes) {
                return Err(AddressError::InvalidChecksum);
            }
            let namespace_buf = namespace_number.to_be_bytes();
            let payload = [&namespace_buf, sub_addr_bytes].concat();

            AddressData {
                protocol,
                payload,
                bytes,
                coin_type: coin_type.into(),
            }
        }
        Protocol::SECP256K1 | Protocol::ACTOR | Protocol::BLS => {
            let payload_cksm =
                base32::decode(base32_alphabet, raw).ok_or(AddressError::InvalidBase32)?;
            if payload_cksm.len() < CHECKSUM_HASH_LENGTH {
                return Err(AddressError::InvalidAddress);
            }
            let payload = &payload_cksm[..payload_cksm.len() - CHECKSUM_HASH_LENGTH];
            let checksum = &payload_cksm[payload.len()..];
            if protocol == Protocol::SECP256K1 || protocol == Protocol::ACTOR {
                if payload.len() != PAYLOAD_HASH_LENGTH {
                    return Err(AddressError::InvalidAddress);
                }
            }
            if protocol == Protocol::BLS {
                if payload.len() != BLS_PUBLIC_KEY_BYTES {
                    return Err(AddressError::InvalidAddress);
                }
            }

            let bytes = [protocol_byte.as_slice(), payload].concat();

            if !validate_checksum(&bytes, checksum) {
                panic!("Invalid address checksum");
            }
            AddressData {
                protocol,
                payload: payload.to_vec(),
                bytes,
                coin_type: coin_type.into(),
            }
        }
    };
    Ok(addr)
}

/// Converts a filecoin address to a corresponding ETH address
///
///```
/// use fevm_utils::filecoin_to_eth_address;
///

/// // test ID type addresses
/// #[tokio::main]
/// async fn main() {
/// let addr = "t01";
/// assert_eq!(filecoin_to_eth_address(addr, "").await.unwrap(), "0xff00000000000000000000000000000000000001");
/// let addr = "t0100";
/// assert_eq!(filecoin_to_eth_address(addr, "").await.unwrap(), "0xff00000000000000000000000000000000000064");
/// let addr = "t05088";
/// assert_eq!(filecoin_to_eth_address(addr, "").await.unwrap(), "0xff000000000000000000000000000000000013e0");
///
/// // test delegated addresses
/// let addr = "t410fkkld55ioe7qg24wvt7fu6pbknb56ht7pt4zamxa";
/// assert_eq!(filecoin_to_eth_address(addr, "").await.unwrap(), "0x52963ef50e27e06d72d59fcb4f3c2a687be3cfef");
///
/// // test SECP256K1 addresses
/// let addr = "t1ypi542zmmgaltijzw4byonei5c267ev5iif2liy";
/// let addr_id = "t01004";
/// assert_eq!(filecoin_to_eth_address(addr, "https://api.hyperspace.node.glif.io/rpc/v1").await.unwrap(),
/// filecoin_to_eth_address(addr_id, "").await.unwrap());
/// }

/// ```
///
#[async_recursion]
pub async fn filecoin_to_eth_address(address: &str, rpc_url: &str) -> Result<String, AddressError> {
    // let address_data = check_address_string(address, rpc_url).await?;
    let address_data = check_address_string(address)?;
    let addr_buffer = if matches!(address_data.protocol, Protocol::DELEGATED) {
        let sub_addr = &address_data.payload[8..];
        sub_addr.to_vec()
    } else if matches!(address_data.protocol, Protocol::ID) {
        let id = leb::read::unsigned(&mut &address_data.payload[..])
            .map_err(|_| AddressError::InvalidLeb128)?;
        let mut addr_buffer: Vec<u8> = vec![0; ETH_ADDRESS_LENGTH];
        addr_buffer[0] = 255_u8.to_be_bytes()[0];
        let id_bytes = &id.to_be_bytes()[0..8];
        for i in 12..20 {
            addr_buffer[i] = id_bytes[i - 12];
        }
        addr_buffer
    }
    // if an f1-f3 address the path to conversion is thus: f1-f3 -> f0 -> 0x
    else {
        // use an API call to get the corresponding f0 type address from an f1-f3 type address
        let lotus_call = json!({
            "jsonrpc": "2.0",
            "method": "Filecoin.StateLookupID",
            "params": [address, []],
            "id": 1
        });

        let response = reqwest::Client::new()
            .post(rpc_url)
            .json(&lotus_call)
            .send()
            .await;
        let response = response.map_err(|_| AddressError::RPCFailure)?;

        // f0 type address
        let lookup_resp: StateLookupIDResp = response
            .json()
            .await
            .map_err(|_| AddressError::RPCFailure)?;

        return filecoin_to_eth_address(&lookup_resp.result, rpc_url).await;
    };
    let mut s = String::with_capacity(ETH_ADDRESS_LENGTH * 2);
    write!(&mut s, "0x").unwrap();
    for b in addr_buffer {
        write!(&mut s, "{:02x}", b).unwrap();
    }

    info!("ETH equivalent is {}", s);

    Ok(s)
}
