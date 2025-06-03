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
use web_time::{Duration, Instant};

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
    let mut bs_peer = DefaultBsPeer::new(key_manager)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to create peer: {}", e)))?;

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
        .map_err(|e| JsValue::from_str(&format!("Failed to generate plog: {}", e)))?;

    let head_bytes: Vec<u8> = bs_peer.plog().unwrap().head.clone().into();

    // Store our local peer ID for verification later
    let local_peer_id = bs_peer.peer_id.as_ref().unwrap().clone();
    tracing::info!("Local peer ID: {}", local_peer_id);

    // Publish the Plog head Cid to the DHT with retry logic
    let mut attempts = 0;
    let max_attempts = 5;
    let mut delay_ms = 500;

    while attempts < max_attempts {
        let result = bs_peer
            .network_client
            .as_mut()
            .unwrap()
            .command(NetworkCommand::PutRecord {
                key: bs_peer.peer_id.as_ref().unwrap().to_bytes().to_vec(),
                value: head_bytes.clone(),
            })
            .await;

        if result.is_ok() {
            tracing::info!("Successfully published Plog head CID to DHT");
            break;
        }

        attempts += 1;
        if attempts >= max_attempts {
            return Err(JsValue::from_str(
                "Failed to publish Plog head CID to DHT after multiple attempts",
            ));
        }

        tracing::warn!(
            "DHT publish failed (attempt {}/{}), retrying in {}ms",
            attempts,
            max_attempts,
            delay_ms
        );

        // Wait before retrying using web_time
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(delay_ms) {
            // Small yield to allow other tasks to run
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
                .await
                .map_err(|_| JsValue::from_str("Timer error"))?;
        }

        delay_ms *= 2; // Exponential backoff
    }

    // Dial the provided libp2p endpoint
    let mut addr = libp2p_endpoint
        .parse::<Multiaddr>()
        .map_err(|e| JsValue::from_str(&format!("Invalid multiaddr: {}", e)))?;

    let (sender, rx) = oneshot::channel();
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::Dial { addr, sender })
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to dial: {}", e)))?;

    // Wait for dial result with timeout
    let dial_result = rx
        .await
        .map_err(|_| JsValue::from_str("Failed to dial peer: channel closed"))?;

    if let Err(e) = dial_result {
        return Err(JsValue::from_str(&format!("Failed to dial peer: {}", e)));
    }

    tracing::info!("Dialed peer successfully");

    // Subscribe to test-results topic to receive verification result
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::Subscribe {
            topic: "test-results".to_string(),
        })
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to subscribe: {}", e)))?;

    // Also subscribe to test-status topic to send ready signal
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::Subscribe {
            topic: "test-status".to_string(),
        })
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to subscribe: {}", e)))?;

    // Send a message to indicate we're ready for verification
    bs_peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::Publish {
            topic: "test-status".to_string(),
            data: "WASM_READY".as_bytes().to_vec(),
        })
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to publish ready message: {}", e)))?;

    tracing::info!("Setup complete, waiting for verification from native peer");

    // We can't exit yet - the native peer needs time to verify our plog
    // Wait for confirmation on the events stream, but also implement a timeout
    let mut events = bs_peer.events.take().unwrap();
    let mut received_result = false;

    // Set a timeout - 30 seconds should be enough for the native peer to verify
    let start_time = Instant::now();
    let timeout = Duration::from_secs(30);

    while !received_result && start_time.elapsed() < timeout {
        match events.next().await {
            Some(event) => {
                tracing::info!("Received event: {:?}", event);
                // Look for test result message
                if let bs_p2p::events::PublicEvent::Message { topic, data, .. } = event {
                    if topic == "test-results" {
                        let message = String::from_utf8_lossy(&data);
                        if message.starts_with("TEST_RESULT:") {
                            received_result = true;
                            let parts: Vec<&str> = message.split(':').collect();
                            if parts.len() >= 3 && parts[1] == "true" {
                                tracing::info!("Test PASSED: {}", parts[2]);
                            } else {
                                tracing::error!(
                                    "Test FAILED: {}",
                                    if parts.len() >= 3 {
                                        parts[2]
                                    } else {
                                        "Unknown reason"
                                    }
                                );
                                return Err(JsValue::from_str(&format!(
                                    "Test failed: {}",
                                    if parts.len() >= 3 {
                                        parts[2]
                                    } else {
                                        "Unknown reason"
                                    }
                                )));
                            }
                        }
                    }
                }
            }
            None => break,
        }

        // Small delay to avoid busy-waiting
        let small_delay = Instant::now();
        while small_delay.elapsed() < Duration::from_millis(100) {
            // Yield to allow other tasks to run
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
                .await
                .map_err(|_| JsValue::from_str("Timer error"))?;
        }
    }

    if !received_result {
        return Err(JsValue::from_str(
            "Test timed out waiting for verification result",
        ));
    }

    tracing::info!("Test completed successfully");
    Ok(())
}
