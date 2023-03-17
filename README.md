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


## Tests

All tests are written as docstrings. 
To run them: 

```bash

cargo test --doc

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

