use std::{fs::read_to_string, path::PathBuf, str::FromStr};

use fevm_utils::{
    filecoin_to_eth_address, get_provider, get_wallet_signing_provider, send_tx, set_tx_gas,
};

use ethers::{
    providers::Middleware,
    types::{transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest},
};

#[tokio::main]
pub async fn main() {
    colog::init();

    let secret = PathBuf::from("./secrets/secret");
    // rpc for hyperspace testnet
    let rpc_url = "https://api.hyperspace.node.glif.io/rpc/v1";

    let provider = get_provider(rpc_url).unwrap();

    let mnemonic = read_to_string(secret).unwrap();
    let client = get_wallet_signing_provider(provider, &mnemonic)
        .await
        .unwrap();

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
    set_tx_gas(
        &mut fund_tx,
        client.estimate_gas(&tx, None).await.unwrap(),
        gas_price,
    );

    // because of the longer blocktimes we need to increase the number of tries.
    let retries = 10;
    send_tx(&tx.into(), client, retries).await.unwrap();
}
