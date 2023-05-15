#![allow(missing_docs)]

use crate::GAS_LIMIT_MULTIPLIER;
use ethers::prelude::{Http, Provider};
use extras::json::tokenamount;
use filecoin_signer::api::{MessageParams, MessageTxAPI};
use fvm_shared::address::Address as FilecoinAddress;
use fvm_shared::message::Message;
use fvm_shared::MethodNum;
use fvm_shared::{bigint::BigInt, econ::TokenAmount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;

const MAX_FEE: &str = "0";

// Default Message Version used for submitting transactions to the FEVM.
const VERSION: u64 = 0;

/// Defines gas fields required for a transaction on the Filecoin Network.
#[derive(Debug)]
pub struct TransactionGasInfo {
    pub gas_limit: u64,
    pub gas_fee_cap: TokenAmount,
    pub gas_premium: TokenAmount,
}

/// Defines the state fields of an actor on the Filecoin network.
#[derive(Deserialize, Serialize, Debug)]
pub struct StateActorInfo {
    #[serde(skip)]
    pub code: HashMap<String, String>,
    #[serde(skip)]
    pub head: HashMap<String, String>,
    #[serde(rename = "Balance", with = "tokenamount")]
    pub balance: TokenAmount,
    #[serde(rename = "Nonce")]
    pub nonce: u64,
}

/// Creates any multisig message for Filecoin.
///
/// # Examples:
///
/// This example demonstrates the creation of an "Approve" multisig message
/// which approves an existing proposal to a multisig actor.
///
/// ```ignore
/// use fil_actor_multisig::TxnIDParams;
/// use fvm_shared::message::Message;
/// use fil_actor_multisig::Methods::Approve;
/// use crate::get_provider;
///
/// let transaction_id = "0";
/// let sender_address = "f1g4nbnure6oq2tvytw5gsh7atvbo5wt4znxx6qci";
/// let actor_address = "f2qhtaxgybfv7djixraoo337pi345j73keurbwsmi";
///
/// let params: TxnIDParams = TxnIDParams {
///     id: TxnID(i64::from_str(&transaction_id).unwrap()),
///     proposal_hash: vec![],
/// };
///
/// let provider = get_provider("https://api.node.glif.io/");
///
/// let approve_multisig_message: Message = create_multisig_message(
///     Approve,
///     &actor_address,
///     &sender_address,
///     provider.clone()
/// );
///
/// println!("Created Message: {:#?}", approve_multisig_message);
///
/// ```
pub async fn create_multisig_message(
    method: MethodNum,
    multisig_params: MessageParams,
    actor_address: &str,
    sender_address: &str,
    provider: Provider<Http>,
) -> Result<Message, Box<dyn Error>> {
    let nonce = get_nonce(sender_address, provider.clone()).await;

    let mut message = Message {
        version: VERSION,
        to: FilecoinAddress::from_str(actor_address).unwrap(),
        from: FilecoinAddress::from_str(sender_address).unwrap(),
        sequence: nonce,
        value: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
        // Gas parameters is are all initially set to zero.
        gas_limit: 0,
        gas_fee_cap: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
        gas_premium: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
        method_num: method, //
        // We initially set the params to empty bytes.
        params: multisig_params.serialize().unwrap(),
    };

    let gas_info = get_message_gas_info(message.clone(), provider.clone(), MAX_FEE).await;
    message.gas_limit = gas_info.gas_limit;
    message.gas_fee_cap = gas_info.gas_fee_cap;
    message.gas_premium = gas_info.gas_premium;

    Ok(message)
}

/// Retrieves the gas parameters given a filecoin transaction message.
///
/// # Examples:
///
/// ```ignore
/// use fvm_shared::address::Address as FilecoinAddress;
/// use fvm_shared::message::Message;
/// use fvm_shared::{bigint::BigInt, econ::TokenAmount};
/// use fvm_ipld_encoding::RawBytes;
///
/// let mut message = Message {
///     version: 0,
///     to: FilecoinAddress::from_str("f1g4nbnure6oq2tvytw5gsh7atvbo5wt4znxx6qci").unwrap(),
///     from: FilecoinAddress::from_str("f2qhtaxgybfv7djixraoo337pi345j73keurbwsmi").unwrap(),
///     sequence: 1,
///     value: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
///     gas_limit: 0,
///     gas_fee_cap: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
///     gas_premium: TokenAmount::from_atto(BigInt::from_str("0").unwrap()),
///     method_num: 1,
///     params: RawBytes::new(vec![]),
/// };
/// let gas_info = get_message_gas_info(message.clone(), provider.clone(), MAX_FEE).await;
///
/// println!("Gas params: {:#?}", gas_info)
/// ```
///
pub async fn get_message_gas_info(
    unsigned_message: Message,
    provider: Provider<Http>,
    max_fee: &str,
) -> TransactionGasInfo {
    let max_fee = HashMap::from([("MaxFee", max_fee)]);

    let gas_info: MessageTxAPI = provider
        .request::<(MessageTxAPI, HashMap<&str, &str>, ()), MessageTxAPI>(
            "Filecoin.GasEstimateMessageGas",
            (MessageTxAPI::Message(unsigned_message), max_fee, ()),
        )
        .await
        .unwrap();

    let gas_info = gas_info.get_message();
    TransactionGasInfo {
        gas_limit: gas_info.gas_limit * (GAS_LIMIT_MULTIPLIER / 100),
        gas_premium: gas_info.gas_premium,
        gas_fee_cap: gas_info.gas_fee_cap,
    }
}

/// Retrieves the nonce from a given address and an RPC provider.
pub async fn get_nonce(address: &str, provider: Provider<Http>) -> u64 {
    let result: StateActorInfo = provider
        .request::<(&str, ()), StateActorInfo>("Filecoin.StateGetActor", (address, ()))
        .await
        .unwrap();
    result.nonce
}
