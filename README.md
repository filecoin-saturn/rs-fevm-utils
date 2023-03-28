<h1 align="center">
	<br>
	 :nut_and_bolt: 
	<br>
	<br>
	fEVM utils
	<br>
	<br>
	<br>
</h1>

> Repo for fEVM related utility functions in rust



## Getting started

### building the project 🔨
Note that the library requires a nightly version of the rust toolchain. You can change the default toolchain by running:

```bash
rustup override set nightly
```

After which you may build the library

```bash
cargo build --release
```

Update the builtin-actors submodule and then build the mainnet bundle of actors:

```bash

make build-actors

```

You will need a functioning installation of `solc` in order to leverage some of the local-execution functionality.
[solc-select](https://github.com/crytic/solc-select) is recommended.
Follow the instructions on [solc-select](https://github.com/crytic/solc-select) to activate `solc` in your environment.


## Tests

All non-executor tests are written as docstrings. 
To run them: 

```bash

cargo test --doc

```

FVM-executor unit tests can be run with: 

```bash

cargo test

```


## Docs

All public functions should be documented. 

```bash 
cargo doc --open  

```

## Example usage

To test out the functions provided create a `./secrets/secret` file containing your mnemonic string (note this should only be used for testing purposes !).

You can then load and parse the mnemonic as such: 

```rust 
use std::{fs::read_to_string, path::PathBuf, str::FromStr};

use ethers::{
    providers::Middleware,
    types::{transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest},
};
use fevm_utils::{filecoin_to_eth_address, get_signing_provider, send_tx, set_tx_gas};

#[tokio::main]
pub async fn main() {
    colog::init();
    let secret = PathBuf::from("./secrets/secret");
    // rpc for hyperspace testnet
    let rpc_url = "https://api.hyperspace.node.glif.io/rpc/v1";

    let mnemonic = read_to_string(secret).unwrap();
    let client = get_signing_provider(&mnemonic, rpc_url).await.unwrap();

    ...

}

```

We then setup a simple transaction to `t410fkkld55ioe7qg24wvt7fu6pbknb56ht7pt4zamxa`.

```rust 
    ...
    // recipient to send fil to
    let addr = "t410fkkld55ioe7qg24wvt7fu6pbknb56ht7pt4zamxa";
    let eth_addr = filecoin_to_eth_address(addr, "").await.unwrap();

    assert_eq!(eth_addr, "0x52963ef50e27e06d72d59fcb4f3c2a687be3cfef");
    // craft the tx (Filecoin doesn't support legacy transactions)
    let mut fund_tx: TypedTransaction = Eip1559TransactionRequest::new()
        .to(Address::from_str(&eth_addr).unwrap())
        .value(1)
        .from(client.address())
        .into(); // specify the `from` field so that the client knows which account to use

    let gas_price = client.provider().get_gas_price().await.unwrap();
    let tx = fund_tx.clone();
    // be slightly over-conservative with gas costs
    set_tx_gas(
        &mut fund_tx,
        client.estimate_gas(&tx, None).await.unwrap(),
        gas_price,
    );

```


To run this script in full run: 

```rust

RUST_LOG=debug cargo run 

```


### Local executor 


To test out the local fEVM executor functionality create the following contract as `contracts/HelloWorld.sol`:  
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract HelloWorld {
    function sayHelloWorld() public pure returns (string memory) {
        return "Hello World";
    }
}
```

Now run: 

```bash

solc contracts/HelloWorld.sol --output-dir ./build/tests --overwrite --bin --hashes --opcodes --abi

```

The generated `.bin`and `.abi` files are the ones we're interested in for testing local execution. 
To test the contract locally: 

```rust 

const WASM_COMPILED_PATH: &str = "./build/tests/HelloWorld.bin";
const ABI_PATH: &str = "./build/tests/HelloWorld.abi";
use fevm_utils::executor::TestExecutor;

#[test]
pub fn main() {
    // create a local executor
    let mut test_executor = TestExecutor::new().unwrap();

    // deploy hellow world using test address 0
    let mut contract = test_executor.deploy(WASM_COMPILED_PATH, ABI_PATH, None).unwrap();

    // call helloworld using test address 0
    test_executor
        .call_fn(&mut contract, "sayHelloWorld", &[])
        .unwrap();

    // print gas usage
    let table = contract.create_gas_table();

    table.print_tty(true).unwrap();
}

```

