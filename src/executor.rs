use cid::Cid;
use ethers::abi::Token;
use ethers_solc::Project;
use fil_actor_eam::Return;
use fil_actor_evm::Method as EvmMethods;
use fil_actors_runtime::EAM_ACTOR_ADDR;
use fvm::executor::{ApplyKind, ApplyRet, Executor};
use fvm::gas::Gas;
use fvm::machine::Manifest;
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
use log::{info, trace};
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

///
const PARAMS_CBOR_HEADER: &str = "58";

///
#[allow(unused)]
pub struct TestExecutor {
    tester: Tester<MemoryBlockstore, DummyExterns>,
    sender: [Account; 300],
    sequence: HashMap<Account, u64>,
}

impl TestExecutor {
    ///
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let (mut tester, _manifest) = setup_tester()?;

        // NOTE: can't be less than 200
        let sender: [Account; 300] = tester.create_accounts()?;

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

        let sequence = HashMap::from_iter(sender.into_iter().zip(vec![0; sender.len()]));

        Ok(TestExecutor {
            tester,
            sender,
            sequence,
        })
    }
}

impl Debug for TestExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestExecutor")
            .field("executor", &"DefaultExecutor")
            .field("constructor_params", &"ExternalParams")
            .field("sender", &self.sender[0])
            .finish()
    }
}

///
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct CallResult {
    result: ApplyRet,
    gas_used: (String, u64),
}

///
#[derive(Debug)]
#[allow(unused)]
pub struct Contract {
    id: u64,
    calls: Vec<CallResult>,
    abi: ethers::abi::Abi,
}

impl Contract {
    ///
    pub fn deploy(
        test_executor: &mut TestExecutor,
        sender_idx: usize,
        wasm_compiled_path: &str,
        abi_path: &str,
    ) -> Result<Self, Box<dyn Error>> {
        // First we deploy the contract in order to actually have an actor running on the embryo address
        info!("Calling init actor (EVM)");

        let evm_bin = load_evm(wasm_compiled_path)?;

        let constructor_params = CreateExternalParams(evm_bin);

        let sender = test_executor.sender[sender_idx];
        let sequence = test_executor.sequence.get_mut(&sender).unwrap();

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

        let res = test_executor
            .tester
            .executor
            .as_mut()
            .unwrap()
            .execute_message(message, ApplyKind::Explicit, 100)?;

        assert_eq!(res.msg_receipt.exit_code.value(), 0);

        let exec_return: Return = RawBytes::deserialize(&res.msg_receipt.return_data).unwrap();

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

        Ok(Self {
            id: contract_actor_id,
            calls: vec![CallResult {
                result: res,
                gas_used: ("deploy".into(), gas_used),
            }],
            abi: load_abi(abi_path)?,
        })
    }

    ///
    pub fn call_fn(
        &mut self,
        test_executor: &mut TestExecutor,
        sender_idx: usize,
        method_name: &str,
        tokens: &[Token],
    ) -> Result<(), Box<dyn Error>> {
        let mut params = hex::decode(PARAMS_CBOR_HEADER).unwrap();

        let abi_func = self.abi.function(method_name).unwrap();

        let call_bytes: Vec<u8> = abi_func.encode_input(tokens).unwrap();
        let num_bytes = call_bytes.len().to_be_bytes();
        let num_bytes = num_bytes.iter().filter(|x| **x != 0);
        params.extend(num_bytes);
        params.extend(call_bytes);

        let params = RawBytes::new(params);

        let sender = test_executor.sender[sender_idx];
        let sequence = test_executor.sequence.get_mut(&sender).unwrap();
        let message = Message {
            from: sender.1,
            to: Address::new_id(self.id),
            gas_limit: 1000000000,
            method_num: EvmMethods::InvokeContract as u64,
            sequence: sequence.clone(),
            params,
            ..Message::default()
        };

        *sequence = *sequence + 1;

        let res = test_executor
            .tester
            .executor
            .as_mut()
            .unwrap()
            .execute_message(message, ApplyKind::Explicit, 100)?;
        let gas_used = parse_gas(&res.exec_trace);

        self.calls.push(CallResult {
            result: res.clone(),
            gas_used: (method_name.into(), gas_used),
        });
        Ok(())
    }

    ///
    pub fn last_call(&self) -> CallResult {
        self.calls[self.calls.len() - 1].clone()
    }

    ///
    pub fn create_gas_table(&self) -> Table {
        let mut table = Table::new();
        table.add_row(row!["Function", "Gas"]);
        self.calls.iter().for_each(
            |CallResult {
                 result: _,
                 gas_used: (description, gas),
             }| {
                table.add_row(row![description, gas]);
            },
        );

        table
    }
}

///
pub fn setup_tester() -> Result<(Tester<MemoryBlockstore, DummyExterns>, Manifest), Box<dyn Error>>
{
    let bs = MemoryBlockstore::default();
    let actors = std::fs::read("./builtin-actors/output/builtin-actors-mainnet.car")?;
    let bundle_root = bundle::import_bundle(&bs, &actors)?;

    let (manifest_version, manifest_data_cid): (u32, Cid) =
        bs.get_cbor(&bundle_root).unwrap().unwrap();
    let manifest = Manifest::load(&bs, &manifest_data_cid, manifest_version)?;

    let tester = Tester::new(NetworkVersion::V18, StateTreeVersion::V5, bundle_root, bs)?;

    return Ok((tester, manifest));
}

///
pub fn compile_project_contracts() -> Result<(), Box<dyn Error>> {
    // configure the project with all its paths, solc, cache etc.
    let project = Project::builder().build()?;
    let output = project.compile()?;

    trace!("compile output {}", output);

    // Tell Cargo that if a source file changes, to rerun this build script.
    project.rerun_if_sources_changed();
    Ok(())
}

///
pub fn load_evm(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let wasm_path = std::env::current_dir().unwrap().join(path).canonicalize()?;
    let evm_hex = std::fs::read(wasm_path)?;

    Ok(hex::decode(evm_hex)?)
}

///
pub fn load_abi(path: &str) -> Result<ethers::abi::Abi, Box<dyn Error>> {
    let abi_path = std::env::current_dir().unwrap().join(path).canonicalize()?;
    let f = File::open(abi_path)?;
    let abi = ethers::abi::Abi::load(f)?;

    Ok(abi)
}

///
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

    use ethers::abi::{Address, Token};

    use super::*;

    #[test]
    fn precompiles_tests() {
        println!("Testing solidity API");

        let mut test_executor = TestExecutor::new().unwrap();

        let mut contract =
            Contract::deploy(&mut test_executor, 0, WASM_COMPILED_PATH, ABI_PATH).unwrap();

        // println!("Calling `resolve_address`");
        // let params = RawBytes::new(hex::decode("58841D5F67A4000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000015011EDA43D05CA6D7D637E7065EF6B8C5DB89E5FB0C0000000000000000000000").unwrap());

        // contract
        //     .call_fn(&mut test_executor, 0, "resolve_address")
        //     .unwrap();
        // let call = contract.last_call();

        // assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        // assert_eq!(
        //     hex::encode(call.result.msg_receipt.return_data.bytes()),
        //     "58200000000000000000000000000000000000000000000000000000000000000064"
        // );

        // println!(
        //     "{}",
        //     call.result
        //         .msg_receipt
        //         .return_data
        //         .deserialize::<String>()
        //         .unwrap()
        // );

        // println!("Calling `lookup_delegated_address (empty response)`");

        // let params = RawBytes::new(
        //     hex::decode(
        //         "58249898B39A0000000000000000000000000000000000000000000000000000000000000064",
        //     )
        //     .unwrap(),
        // );

        // contract
        //     .call_fn(
        //         &mut test_executor,
        //         0,
        //         params,
        //         "lookup_delegated_address (empty response)",
        //     )
        //     .unwrap();
        // let call = contract.last_call();

        // assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        // assert_eq!(hex::encode(call.result.msg_receipt.return_data.bytes()), "584000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000");

        // println!("Calling `lookup_delegated_address (address found)`");

        // let params = RawBytes::new(
        //     hex::decode(
        //         "58249898B39A0000000000000000000000000000000000000000000000000000000000000190",
        //     )
        //     .unwrap(),
        // );

        // contract
        //     .call_fn(
        //         &mut test_executor,
        //         0,
        //         params,
        //         "lookup_delegated_address (address found)",
        //     )
        //     .unwrap();
        // let call = contract.last_call();

        // assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        // assert_eq!(hex::encode(call.result.msg_receipt.return_data.bytes()), "586000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000016040adafea492d9c6733ae3d56b7ed1adb60692c98bc500000000000000000000");

        println!("Calling `resolve_eth_address`");

        let tokens = &[Token::Address(
            Address::from_str("0xDAFEA492D9C6733AE3D56B7ED1ADB60692C98BC5").unwrap(),
        )];

        contract
            .call_fn(&mut test_executor, 0, "resolve_eth_address", tokens)
            .unwrap();
        let call = contract.last_call();
        assert_eq!(call.result.msg_receipt.exit_code.value(), 0);
        assert_eq!(
            hex::encode(call.result.msg_receipt.return_data.bytes()),
            "58200000000000000000000000000000000000000000000000000000000000000190"
        );

        let table = contract.create_gas_table();

        table.print_tty(true).unwrap();
    }
}
