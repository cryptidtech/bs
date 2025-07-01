#![cfg(target_arch = "wasm32")]
use bs_p2p::events::api::NetworkCommand;
use bs_p2p::events::PublicEvent;
use bs_peer::utils::setup_initialized_network_peer;
use futures::channel::oneshot;
use futures::StreamExt;
use gloo_timers::future::sleep;
use libp2p::Multiaddr;
use wasm_bindgen::prelude::*;
use web_time::Duration;

#[wasm_bindgen]
pub async fn run_test_wasm(libp2p_endpoint: String) -> Result<(), JsValue> {
    tracing_wasm::set_as_global_default();
    tracing::info!(
        "Running wasm test with libp2p endpoint: {}",
        libp2p_endpoint
    );

    tracing::info!("Starting peerpiper-native TESTS");

    let mut fixture = setup_initialized_network_peer().await.unwrap();

    tracing::info!("Peer initialized successfully {:?}", fixture.peer);

    let local_peer_id = fixture.peer.peer_id.as_ref().unwrap().clone();

    tracing::info!("Local peer ID: {}", local_peer_id);

    // Dial the provided libp2p endpoint
    let addr = libp2p_endpoint.parse::<Multiaddr>().unwrap();

    fixture
        .peer
        .network_client
        .as_mut()
        .unwrap()
        .dial(addr)
        .await
        .unwrap();

    tracing::info!("Dialed peer successfully");

    loop {
        match fixture
            .peer
            .events
            .as_mut()
            .unwrap()
            .select_next_some()
            .await
        {
            PublicEvent::NewConnection { peer: _ } => {
                break;
            }
            evt => {
                tracing::info!("Other event: {:?}", evt);
            }
        }
    }

    // Now that we've confirmed the connection, send the ready signal
    tracing::info!("Connection confirmed");

    // wasm32 sleep for a few seconds to let the DHT sync
    let n = 6;
    tracing::info!("Sleeping for {} seconds to allow DHT sync", n);
    sleep(Duration::from_secs(n)).await;

    tracing::info!("Woke up after {} seconds", n);

    // put the plog head as a record for PeerId bytes inthe DHT.
    // Extract the plog head bytes that we'll share when requested
    let head_bytes: Vec<u8> = fixture
        .peer
        .plog()
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .head
        .clone()
        .into();

    fixture
        .peer
        .network_client
        .as_mut()
        .unwrap()
        .command(NetworkCommand::PutRecord {
            key: local_peer_id.into(),
            value: head_bytes,
        })
        .await
        .unwrap();

    tracing::info!("Plog head bytes put in DHT");

    loop {
        match fixture
            .peer
            .events
            .as_mut()
            .unwrap()
            .select_next_some()
            .await
        {
            PublicEvent::NewConnection { peer: _ } => {
                break;
            }
            evt => {
                tracing::info!("Other event: {:?}", evt);
            }
        }
    }
    Ok(())
}
