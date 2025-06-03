#![cfg(target_arch = "wasm32")]
use bs::{
    config::sync::{KeyManager, MultiSigner},
    params::anykey::PubkeyParams,
};
use bs_p2p::events::api::NetworkCommand;
use bs_peer::test_utils::setup_initialized_peer;
use bs_peer::{peer::DefaultBsPeer, platform::Blockstore};
use bs_wallets::memory::InMemoryKeyManager;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use libp2p::Multiaddr;
use provenance_log::{entry::Field, key::key_paths::ValidatedKeyParams as _};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

#[wasm_bindgen]
pub async fn run_test_wasm(libp2p_endpoint: String) -> Result<(), JsValue> {
    tracing_wasm::set_as_global_default();
    tracing::info!(
        "Running wasm test with libp2p endpoint: {}",
        libp2p_endpoint
    );

    tracing::info!("Starting peerpiper-native TESTS");

    let key_manager = InMemoryKeyManager::<bs_peer::Error>::default();

    // Create a new peer with the default platform blockstore
    let mut bs_peer = DefaultBsPeer::new(key_manager).await.unwrap();

    let entry_key = Field::ENTRY;
    let proof_key = Field::PROOF;
    let pubkey = PubkeyParams::KEY_PATH;

    let unlock_script = format!(
        r#"
         // push the serialized Entry as the message
         push("{entry_key}");

         // push the proof data
         push("{proof_key}");
    "#
    );

    let lock_script = format!(
        r#"
            // then check a possible threshold sig...
            check_signature("/recoverykey", "{entry_key}") ||

            // then check a possible pubkey sig...
            check_signature("{pubkey}", "{entry_key}") ||
            
            // then the pre-image proof...
            check_preimage("/hash")
        "#
    );

    // Initialize the peer
    bs_peer
        .generate(&lock_script, &unlock_script)
        .await
        .unwrap();

    let head_bytes: Vec<u8> = bs_peer.plog().unwrap().head.clone().into();

    // Publish the Plog head Cid to the DHT
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::PutRecord {
            key: bs_peer.peer_id.as_ref().unwrap().to_bytes().to_vec(),
            value: head_bytes,
        });

    // Dial the provided libp2p endpoint
    let mut addr = libp2p_endpoint.parse::<Multiaddr>().unwrap();
    let (sender, rx) = oneshot::channel();
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::Dial { addr, sender })
        .await
        .unwrap();

    // should rx Ok(())
    let _ = rx
        .await
        .map_err(|_| JsValue::from_str("Failed to dial peer"))?;

    tracing::info!("Dialed peer successfully");

    // tracing::info!("End of browser test script.");
    Ok(())
}
