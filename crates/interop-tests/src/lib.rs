#![cfg(target_arch = "wasm32")]
use bs_p2p::events::api::NetworkCommand;
use bs_p2p::events::PublicEvent;
use bs_peer::utils::setup_initialized_network_peer;
use console_error_panic_hook;
use futures::StreamExt;
use gloo_timers::future::sleep;
use gloo_timers::future::TimeoutFuture;
use libp2p::Multiaddr;
use std::sync::Once;
use wasm_bindgen::prelude::*;
use web_time::Duration;

#[wasm_bindgen]
pub async fn run_test_wasm(libp2p_endpoint: String) -> Result<(), JsValue> {
    // Set up tracing/panic hook only once
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_wasm::set_as_global_default();
        console_error_panic_hook::set_once();
    });

    tracing::info!(
        "Running wasm test with libp2p endpoint: {}",
        libp2p_endpoint
    );

    let mut fixture = setup_initialized_network_peer()
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to init peer: {:?}", e)))?;

    let local_peer_id = fixture
        .peer
        .peer_id
        .as_ref()
        .ok_or_else(|| JsValue::from_str("Missing peer_id"))?
        .clone();

    let addr = libp2p_endpoint
        .parse::<Multiaddr>()
        .map_err(|e| JsValue::from_str(&format!("Failed to parse multiaddr: {:?}", e)))?;

    fixture
        .peer
        .network_client
        .as_mut()
        .ok_or_else(|| JsValue::from_str("Missing network_client"))?
        .dial(addr)
        .await
        .map_err(|e| JsValue::from_str(&format!("Failed to dial: {:?}", e)))?;

    tracing::info!("Dialed peer successfully");

    // Wait for connection event with timeout
    // let mut events = fixture
    //     .peer
    //     .events
    //     .as_mut()
    //     .ok_or_else(|| JsValue::from_str("Missing events"))?;

    // If the NewConnection event is not received within 15 seconds, we will timeout.
    let timeout_fut = TimeoutFuture::new(15_000);

    // join the two futures: the timeout and the event stream
    let connection_result = tokio::select! {
        event = fixture
        .peer
        .events
        .as_mut()
        .ok_or_else(|| JsValue::from_str("Missing events"))?.select_next_some() => {
            match event {
                PublicEvent::NewConnection { peer, .. }  => {
                    tracing::info!("Received NewConnection event for peer: {:?}", peer);
                    Ok(())
                },
                evt => {
                    tracing::warn!("Unexpected event: {:?}", evt);
                    Err(JsValue::from_str("Unexpected event received"))
                }
            }
        }
        // If the timeout occurs, we return an error
        _ = timeout_fut => Err(JsValue::from_str("Timed out waiting for connection")),
    };

    connection_result.map_err(|_| JsValue::from_str("Timed out waiting for connection"))?;

    tracing::info!("Connection confirmed");

    sleep(Duration::from_secs(6)).await;

    tracing::info!("Woke up after sleep");

    // Safely extract head bytes (avoid blocking Mutex in wasm)
    let head_bytes: Vec<u8> = {
        let plog = fixture.peer.plog().clone(); // If possible, make this async!
        let Some(plog) = plog.as_ref() else {
            return Err(JsValue::from_str("No plog found"));
        };
        plog.head.clone().into()
    };

    fixture
        .peer
        .network_client
        .as_mut()
        .ok_or_else(|| JsValue::from_str("Missing network_client"))?
        .command(NetworkCommand::PutRecord {
            key: local_peer_id.into(),
            value: head_bytes,
        })
        .await
        .map_err(|e| JsValue::from_str(&format!("PutRecord failed: {:?}", e)))?;

    tracing::info!("Plog head bytes put in DHT");

    // Wait for another event (with timeout)
    let event_result = tokio::select! {
        _ = TimeoutFuture::new(15_000) => Err(JsValue::from_str("Timed out waiting for second connection")),
        event = fixture
        .peer
        .events
        .as_mut()
        .ok_or_else(|| JsValue::from_str("Missing events"))?.select_next_some() => {
            match event {
                PublicEvent::NewConnection { peer, .. } if peer == local_peer_id.to_string() => {
                    tracing::info!("Received second NewConnection event for local peer: {:?}", peer);
                    Ok(())
                },
                PublicEvent::NewConnection { peer, .. } => {
                    tracing::warn!("Received second NewConnection event for different peer: {:?}", peer);
                    Err(JsValue::from_str("Received second NewConnection for different peer"))
                },
                evt => {
                    tracing::warn!("Unexpected event: {:?}", evt);
                    Err(JsValue::from_str("Unexpected event received"))
                }
            }
        }
    };

    event_result.map_err(|_| JsValue::from_str("Timed out waiting for second connection"))?;

    Ok(())
}
