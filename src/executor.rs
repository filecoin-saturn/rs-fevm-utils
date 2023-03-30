use cid::Cid;
use ethers::abi::encode;
use ethers::abi::{decode, ParamType, Token};
use fil_actor_eam::Return;
use fil_actor_evm::Method as EvmMethods;
use fil_actors_runtime::EAM_ACTOR_ADDR;
use fvm::executor::{ApplyKind, ApplyRet, Executor};
use fvm::gas::Gas;
use fvm::machine::{Machine, Manifest};
use fvm::trace::{ExecutionEvent, ExecutionTrace};
use fvm_integration_tests::bundle;
use fvm_integration_tests::dummy::DummyExterns;
use fvm_integration_tests::tester::Account;
use fvm_integration_tests::tester::Tester;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::{strict_bytes, CborStore, RawBytes};
use fvm_shared::address::Address;
use fvm_shared::bigint::Zero;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::state::StateTreeVersion;
use fvm_shared::version::NetworkVersion;
use log::{error, info};
use prettytable::{row, Table};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::fs::File;

#[derive(SerdeSerialize, SerdeDeserialize, Debug)]
#[serde(transparent)]
///
pub struct CreateExternalParams(#[serde(with = "strict_bytes")] pub Vec<u8>);

///
pub type GasResult = Vec<(String, u64)>;

/// calldata is encoding as a byte array of variable length with length encoded by (1, 2, 4, 8 bytes)
const PARAMS_CBOR_HEADER: [&str; 4] = ["58", "59", "5a", "5b"];

#[derive(thiserror::Error, Debug)]
/// Errors related to address parsing
#[allow(missing_docs)]
pub enum ExecutorError {
    #[error("uninitialized state")]
    UninitializedState,
    #[error("uninitialized executor")]
    UninitializedExecutor,
    #[error("uninitialized sequence")]
    UninitializedSequence,
    #[error("unnable to load actors")]
    BadActors,
    #[error("incorrectly formatted params")]
    BadParams,
}

///
#[allow(unused)]
pub struct TestExecutor {
    tester: Tester<MemoryBlockstore, DummyExterns>,
    accounts: [Account; 300],
    sequence: HashMap<Account, u64>,
    sender: usize,
}

impl TestExecutor {
    /// Instantiates a new local executor. Requires a local build of `builtin-actors`.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let (mut tester, _manifest) = setup_tester()?;

        // NOTE: can't be less than 200
        let accounts: [Account; 300] = tester.create_accounts()?;

        // Create embryo address to deploy a contract on it (+ assign some FILs to it)
        // TODO: make this random
        let tmp = hex::decode("DAFEA492D9c6733ae3d56b7Ed1ADB60692c98Bc5")?;
        let embryo_eth_address = tmp.as_slice();
        let embryo_delegated_address = Address::new_delegated(10, embryo_eth_address)?;
        tester.create_placeholder(&embryo_delegated_address, TokenAmount::from_whole(100))?;

        info!("Embryo address delegated [{}]", embryo_delegated_address);
        info!(
            "Embryo address delegated hex [{}]",
            hex::encode(embryo_delegated_address.to_bytes())
        );

        // Instantiate machinerust
        tester.instantiate_machine(DummyExterns)?;

        let sequence = HashMap::from_iter(accounts.into_iter().zip(vec![0; accounts.len()]));

        Ok(TestExecutor {
            tester,
            accounts,
            sequence,
            // default account to make calls from
            sender: 0,
        })
    }

    /// Fetches an account by index
    pub fn get_account(&self, idx: usize) -> Result<Account, Box<dyn Error>> {
        if idx >= self.accounts.len() {
            return Err(ExecutorError::UninitializedState.into());
        }
        Ok(self.accounts[idx])
    }

    /// Fetches currently active account
    pub fn current_sender(&self) -> Account {
        self.accounts[self.sender]
    }

    /// Fetches balance for a specific actor id
    pub fn get_balance(&self, actor_id: u64) -> Result<TokenAmount, Box<dyn Error>> {
        Ok(self
            .tester
            .executor
            .as_ref()
            .ok_or_else(|| ExecutorError::UninitializedExecutor)?
            .state_tree()
            .get_actor(actor_id)
            .map_err(|_| ExecutorError::UninitializedState)?
            .ok_or_else(|| ExecutorError::UninitializedState)?
            .balance)
    }

    /// Updates the currently active account to make calls with
    pub fn update_active_account(&mut self, idx: usize) {
        self.sender = idx
    }

    /// Sends funds from an account to an address
    pub fn send_funds(
        &mut self,
        to: Address,
        value: TokenAmount,
    ) -> Result<ApplyRet, Box<dyn Error>> {
        let sequence = self
            .sequence
            .get_mut(&self.accounts[self.sender])
            .ok_or_else(|| ExecutorError::UninitializedSequence)?;

        let message = Message {
            from: self.accounts[self.sender].1,
            to,
            gas_limit: 1000000000,
            value,
            sequence: sequence.clone(),
            ..Message::default()
        };

        *sequence = *sequence + 1;

        let res = self
            .tester
            .executor
            .as_mut()
            .ok_or_else(|| ExecutorError::UninitializedExecutor)?
            .execute_message(message, ApplyKind::Explicit, 100)?;

        Ok(res)
    }

    /// deploys a new contract using a instantiated test executor, an account to pay for gas, and paths to solc generated `.bin` and `.abi` files for a solidity contract.
    pub fn deploy(
        &mut self,
        wasm_compiled_path: &str,
        abi_path: &str,
        constructor_args: Option<&[Token]>,
    ) -> Result<Contract, Box<dyn Error>> {
        // First we deploy the contract in order to actually have an actor running on the embryo address
        info!("Calling init actor (EVM)");

        let mut evm_bin = load_evm(wasm_compiled_path)?;

        match constructor_args {
            None => (),
            Some(constructor_args) => evm_bin.append(&mut encode(constructor_args)),
        }

        let constructor_params = CreateExternalParams(evm_bin);

        let sender = self.accounts[self.sender];
        let sequence = self
            .sequence
            .get_mut(&sender)
            .ok_or_else(|| ExecutorError::UninitializedSequence)?;

        let message = Message {
            from: sender.1,
            to: EAM_ACTOR_ADDR,
            gas_limit: 1000000000,
            method_num: 4,
            sequence: sequence.clone(),
            params: RawBytes::serialize(constructor_params)?,
            ..Message::default()
        };

        *sequence = *sequence + 1;

        let res = self
            .tester
            .executor
            .as_mut()
            .ok_or_else(|| ExecutorError::UninitializedExecutor)?
            .execute_message(message, ApplyKind::Explicit, 100)?;

        assert_eq!(res.msg_receipt.exit_code.value(), 0);

        let exec_return: Return = RawBytes::deserialize(&res.msg_receipt.return_data)?;

        info!(
            "Contract address [{}]",
            hex::encode(Address::new_id(exec_return.actor_id).to_bytes())
        );

        match exec_return.robust_address {
            Some(addr) => println!("Contract address robust type [{}]", addr),
            None => (),
        }

        info!(
            "Contract address eth address type [{}]",
            hex::encode(exec_return.eth_address.0)
        );

        let contract_actor_id = exec_return.actor_id;

        let gas_used = parse_gas(&res.exec_trace);

        Ok(Contract {
            id: contract_actor_id,
            calls: vec![CallResult {
                result: res,
                gas_used: ("deploy".into(), gas_used),
            }],
            address: Address::new_id(exec_return.actor_id),
            abi: load_abi(abi_path)?,
        })
    }

    /// Calls a function on a deployed contract using a instantiated test executor, an account to pay for gas, a method name to call and a list of tokens / parameters to call.
    pub fn call_fn(
        &mut self,
        contract: &mut Contract,
        method_name: &str,
        tokens: &[Token],
    ) -> Result<(), Box<dyn Error>> {
        let abi_func = contract.abi.function(method_name)?;

        let call_bytes: Vec<u8> = abi_func.encode_input(tokens)?;

        let num_bytes = call_bytes.len().to_be_bytes();
        let num_bytes = num_bytes
            .iter()
            .filter(|x| **x != 0)
            .map(|x| x.clone())
            .collect::<Vec<u8>>();
        let mut params = hex::decode(PARAMS_CBOR_HEADER[num_bytes.len() - 1])?;
        params.extend(num_bytes);
        params.extend(call_bytes);

        info!(
            "{} call params:  {}",
            method_name,
            hex::encode(params.clone())
        );

        let check = serde_cbor::from_slice::<&[u8]>(&params);
        // assert its well formatted cbor
        if !(check.is_ok()) {
            error!("bad cbor {:?}", check);
            return Err(ExecutorError::BadParams.into());
        }

        let params = RawBytes::new(params);

        let sender = self.accounts[self.sender];
        let sequence = self
            .sequence
            .get_mut(&sender)
            .ok_or_else(|| ExecutorError::UninitializedSequence)?;
        let message = Message {
            from: sender.1,
            to: Address::new_id(contract.id),
            gas_limit: 1000000000,
            method_num: EvmMethods::InvokeContract as u64,
            sequence: sequence.clone(),
            params,
            ..Message::default()
        };

        *sequence = *sequence + 1;

        let res = self
            .tester
            .executor
            .as_mut()
            .ok_or_else(|| ExecutorError::UninitializedExecutor)?
            .execute_message(message, ApplyKind::Explicit, 100)?;
        let gas_used = parse_gas(&res.exec_trace);

        contract.calls.push(CallResult {
            result: res.clone(),
            gas_used: (method_name.into(), gas_used),
        });
        Ok(())
    }
}

impl Debug for TestExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestExecutor")
            .field("executor", &"DefaultExecutor")
            .field("constructor_params", &"ExternalParams")
            .field("sender", &self.accounts[0])
            .finish()
    }
}

///
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct CallResult {
    /// result from call
    pub result: ApplyRet,
    /// tuple of ("label", gas_consumed)
    pub gas_used: (String, u64),
}

impl CallResult {
    /// decode a cbor encoded receipt
    pub fn decode_return_data(&self, types: &[ParamType]) -> Result<Vec<Token>, Box<dyn Error>> {
        let data = serde_cbor::from_slice::<&[u8]>(&self.result.msg_receipt.return_data)?;
        Ok(decode(types, data)?)
    }
}

/// Represents a Filecoin address
#[derive(Debug)]
pub struct FilAddress {
    data: Vec<u8>,
}

impl FilAddress {
    /// constructor
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    /// converts to eth token
    pub fn to_eth_token(&self) -> Token {
        Token::Tuple(vec![Token::Bytes(self.data.clone())])
    }
    /// returns eth param type
    pub fn param_type(&self) -> ParamType {
        ParamType::Tuple(vec![ParamType::Bytes])
    }
}

/// Contract type
#[derive(Debug)]
#[allow(unused)]
pub struct Contract {
    /// contract actor id
    pub id: u64,
    /// contract address
    pub address: Address,
    calls: Vec<CallResult>,
    abi: ethers::abi::Abi,
}

impl Contract {
    /// gets the last call made to a contract
    pub fn last_call(&self) -> CallResult {
        self.calls[self.calls.len() - 1].clone()
    }

    /// creates a gas table across previous calls to contract functions
    pub fn create_gas_table(&self) -> Table {
        let mut table = Table::new();
        table.add_row(row!["Function", "Gas"]);
        self.calls.iter().for_each(
            |CallResult {
                 gas_used: (description, gas),
                 ..
             }| {
                table.add_row(row![description, gas]);
            },
        );

        table
    }
}

/// Helper function for creating a tester. Requires a build of the mainnet-bundle from `builtin-actors`
pub fn setup_tester() -> Result<(Tester<MemoryBlockstore, DummyExterns>, Manifest), Box<dyn Error>>
{
    let bs = MemoryBlockstore::default();
    let actors = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/builtin-actors/output/builtin-actors-mainnet.car"
    ));

    let bundle_root = bundle::import_bundle(&bs, &actors[..])?;

    let (manifest_version, manifest_data_cid): (u32, Cid) = match bs.get_cbor(&bundle_root)? {
        Some(b) => b,
        None => return Err(Box::new(ExecutorError::BadActors)),
    };
    let manifest = Manifest::load(&bs, &manifest_data_cid, manifest_version)?;

    let tester = Tester::new(NetworkVersion::V18, StateTreeVersion::V5, bundle_root, bs)?;

    return Ok((tester, manifest));
}

///
pub fn load_evm(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let wasm_path = std::env::current_dir()?.join(path).canonicalize()?;
    let evm_hex = std::fs::read(wasm_path)?;

    Ok(hex::decode(evm_hex)?)
}

///
pub fn load_abi(path: &str) -> Result<ethers::abi::Abi, Box<dyn Error>> {
    let abi_path = std::env::current_dir()?.join(path).canonicalize()?;
    let f = File::open(abi_path)?;
    let abi = ethers::abi::Abi::load(f)?;

    Ok(abi)
}

/// parses gas results from an [ExecutionTrace]
pub fn parse_gas(exec_trace: &ExecutionTrace) -> u64 {
    let mut depth = -1; // start at -1 because we have the on chain message gas and then the call to our solidity contract
    let mut gas_usage = Gas::new(0);

    for exec in exec_trace {
        let gas = match &exec {
            ExecutionEvent::GasCharge(gc) => gc.total(),
            ExecutionEvent::Call { .. } => {
                depth += 1;
                Gas::zero()
            }
            ExecutionEvent::CallReturn(..) => {
                depth -= 1;
                Gas::zero()
            }
            _ => Gas::zero(),
        };

        if depth <= 0 {
            gas_usage += gas;
        }
    }

    return gas_usage.round_down();
}

#[cfg(test)]
mod executortests {

    // this file was kindly compiled
    const WASM_COMPILED_PATH: &str = "./test_files/PrecompilesApiTest.bin";
    const ABI_PATH: &str = "./test_files/PrecompilesApiTest.json";

    use std::str::FromStr;

    use ethers::{
        abi::{Address, ParamType, Token},
        types::U256,
    };

    use super::*;

    #[test]
    fn precompiles_tests() {
        println!("Testing solidity API");

        let mut test_executor = TestExecutor::new().unwrap();

        let mut contract = test_executor
            .deploy(WASM_COMPILED_PATH, ABI_PATH, None)
            .unwrap();

        println!("Calling `resolve_address`");
        // type 1 address encoded as bytes

        let token = FilAddress {
            data: hex::decode("011EDA43D05CA6D7D637E7065EF6B8C5DB89E5FB0C").unwrap(),
        }
        .to_eth_token();

        test_executor
            .call_fn(&mut contract, "resolve_address", &vec![token])
            .unwrap();
        let call = contract.last_call();

        assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        assert_eq!(
            hex::encode(call.result.msg_receipt.return_data.bytes()),
            "58200000000000000000000000000000000000000000000000000000000000000064"
        );

        // we know from the abi that it returns an int so we decode accordingly
        assert_eq!(
            call.decode_return_data(&vec![ParamType::Uint(256)])
                .unwrap()[0]
                .clone(),
            Token::Uint(U256::from(100))
        );

        println!("Calling `lookup_delegated_address (empty response)`");

        let tokens = &[Token::Uint(U256::from(100))];

        test_executor
            .call_fn(&mut contract, "lookup_delegated_address", tokens)
            .unwrap();
        let call = contract.last_call();

        assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        assert_eq!(hex::encode(call.result.msg_receipt.return_data.bytes()), "584000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(
            call.decode_return_data(&vec![ParamType::Bytes]).unwrap()[0].clone(),
            Token::Bytes(vec![])
        );

        println!("Calling `lookup_delegated_address (address found)`");

        let tokens = &[Token::Uint(U256::from(400))];

        test_executor
            .call_fn(&mut contract, "lookup_delegated_address", tokens)
            .unwrap();
        let call = contract.last_call();

        assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        assert_eq!(hex::encode(call.result.msg_receipt.return_data.bytes()), "586000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000016040adafea492d9c6733ae3d56b7ed1adb60692c98bc500000000000000000000");
        // we decode the f4 address bytes
        assert_eq!(
            call.decode_return_data(&vec![ParamType::Bytes]).unwrap()[0].clone(),
            Token::Bytes(hex::decode("040adafea492d9c6733ae3d56b7ed1adb60692c98bc5").unwrap(),)
        );

        println!("Calling `resolve_eth_address`");

        let tokens = &[Token::Address(
            Address::from_str("0xDAFEA492D9C6733AE3D56B7ED1ADB60692C98BC5").unwrap(),
        )];

        test_executor
            .call_fn(&mut contract, "resolve_eth_address", tokens)
            .unwrap();
        let call = contract.last_call();
        assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        assert_eq!(
            hex::encode(call.result.msg_receipt.return_data.bytes()),
            "58200000000000000000000000000000000000000000000000000000000000000190"
        );

        // we know from the abi that it returns an int so we decode accordingly
        assert_eq!(
            call.decode_return_data(&vec![ParamType::Uint(256)])
                .unwrap()[0]
                .clone(),
            Token::Uint(U256::from(400))
        );

        let table = contract.create_gas_table();

        table.print_tty(true).unwrap();
    }
}

#[cfg(test)]
mod sendtests {

    // this file was kindly compiled
    const WASM_COMPILED_PATH: &str = "./test_files/PrecompilesApiTest.bin";
    const ABI_PATH: &str = "./test_files/PrecompilesApiTest.json";

    use super::*;

    #[test]
    fn precompiles_tests() {
        println!("Testing sending funds");

        let mut test_executor = TestExecutor::new().unwrap();

        let contract = test_executor
            .deploy(WASM_COMPILED_PATH, ABI_PATH, None)
            .unwrap();

        let actor_id = test_executor.accounts[0].0;

        let balance = test_executor.get_balance(actor_id).unwrap();
        assert_eq!(balance, TokenAmount::from_atto(10000));

        // send from the currently active account i.e `sender` on the TestExecutor
        let send_res = test_executor
            .send_funds(contract.address, TokenAmount::from_atto(10000))
            .unwrap();
        assert_eq!(send_res.msg_receipt.exit_code.value(), 0);

        let balance = test_executor.get_balance(actor_id).unwrap();
        assert_eq!(balance, TokenAmount::from_atto(0));

        let balance = test_executor.get_balance(contract.id).unwrap();
        assert_eq!(balance, TokenAmount::from_atto(10000))
    }
}
