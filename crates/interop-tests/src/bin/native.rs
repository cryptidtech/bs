#![cfg(not(target_arch = "wasm32"))]

use bs::config::sync::{KeyManager, MultiSigner};
use bs_p2p::events::{api::NetworkCommand, delay::Delay, PublicEvent};
use bs_peer::peer::{get_entry_chain, resolve_plog, DefaultBsPeer, Resolver};
use bs_wallets::memory::InMemoryKeyManager;
use provenance_log::{Entry, Script};

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Router;
use axum::{http::Method, routing::get};
use futures::StreamExt;
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            "interop_tests_native=debug,libp2p_webrtc=info,libp2p_ping=debug,beetswap=trace",
        )
        .try_init();

    tracing::info!("Starting peerpiper-native TESTS");

    let key_manager = InMemoryKeyManager::<bs_peer::Error>::default();

    // Create a new peer with the default platform blockstore
    let bs_peer = DefaultBsPeer::new(key_manager).await?;

    // Wrap the peer in Arc<Mutex<>> to safely share between tasks
    let bs_peer = Arc::new(Mutex::new(bs_peer));

    // Create a channel to signal test completion
    let (completion_tx, mut completion_rx) = channel::<(bool, String)>(1);

    // Clone the peer for the address waiting task
    let bs_peer_clone = Arc::clone(&bs_peer);

    // Wait for listen address
    let address = tokio::select! {
        addr = async {
            let mut peer = bs_peer_clone.lock().await;
            loop {
                if let Some(event) = peer.events.as_mut().unwrap().next().await {
                    if let PublicEvent::ListenAddr { address, .. } = event {
                        tracing::info!(%address, "RXD Address");
                        break address;
                    }
                }
            }
        } => addr,
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            tracing::error!("Timed out waiting for listen address");
            return Err("Timed out waiting for listen address".into());
        }
    };

    // Serve .wasm, .js and server multiaddress over HTTP on this address.
    tokio::spawn(serve(address.clone()));

    // Subscribe to test-status topic to receive ready signal from browser
    {
        let mut peer = bs_peer.lock().await;
        if let Some(client) = peer.network_client.as_mut() {
            client
                .command(NetworkCommand::Subscribe {
                    topic: "test-status".to_string(),
                })
                .await?;
        }

        // Also subscribe to test-results to publish verification results
        if let Some(client) = peer.network_client.as_mut() {
            client
                .command(NetworkCommand::Subscribe {
                    topic: "test-results".to_string(),
                })
                .await?;
        }
    }

    let mut test_completed = false;
    let tick = Delay::new(Duration::from_secs(120)); // 2 minute total test timeout
    tokio::pin!(tick);

    loop {
        tokio::select! {
            _ = &mut tick, if !test_completed => {
                test_completed = true;
                tracing::error!("Test timed out after 120 seconds");

                // Publish timeout message
                let mut peer = bs_peer.lock().await;
                if let Some(client) = peer.network_client.as_mut() {
                    let timeout_msg = "TEST_RESULT:false:Test timed out after 120 seconds";
                    let _ = client.command(NetworkCommand::Publish {
                        topic: "test-results".to_string(),
                        data: timeout_msg.as_bytes().to_vec(),
                    }).await;
                }

                return Err("Test timed out".into());
            }

            event_opt = async {
                let mut peer = bs_peer.lock().await;
                peer.events.as_mut().unwrap().next().await
            }, if !test_completed => {
                if let Some(event) = event_opt {
                    tracing::debug!("Received event: {:?}", event);

                    match event {
                        PublicEvent::NewConnection { peer: connected_peer } => {
                            // Once connection establish, process verification
                            tracing::info!("New connection from {}", connected_peer);

                            let p = PeerId::from_str(&connected_peer).unwrap();

                            // Clone Arc to move into the verification task
                            let bs_peer_clone = Arc::clone(&bs_peer);
                            let completion_tx_clone = completion_tx.clone();
                            let completion_tx_clone_clone = completion_tx.clone();

                            tokio::spawn(async move {
                                // Use a timeout for the verification process
                                match tokio::time::timeout(
                                    Duration::from_secs(60),
                                    verify_remote_plog(bs_peer_clone, p, completion_tx_clone)
                                ).await {
                                    Ok(result) => {
                                        result.unwrap();
                                    },
                                    Err(_) => {
                                        tracing::error!("Verification timed out");
                                        let _ = completion_tx_clone_clone.send((
                                            false,
                                            "Verification process timed out".to_string()
                                        )).await;
                                    }
                                }
                            });
                        }
                        PublicEvent::Message { peer, topic, data } => {
                            tracing::info!("Received message from {} on topic {}: {:?}", peer, topic, data);

                            // Check if this is the "WASM_READY" message
                            if topic == "test-status" && String::from_utf8_lossy(&data) == "WASM_READY" {
                                tracing::info!("Browser reported ready, awaiting verification completion");
                            }

                            // Check if this is a test result message (should be from us, but check anyway)
                            if topic == "test-results" {
                                let message = String::from_utf8_lossy(&data);
                                if message.starts_with("TEST_RESULT:") {
                                    test_completed = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            completion = completion_rx.recv(), if !test_completed => {
                if let Some((success, message)) = completion {
                    test_completed = true;

                    // Publish test result
                    let mut peer = bs_peer.lock().await;
                    if let Some(mut client) = peer.network_client.as_mut() {
                        let result_msg = format!("TEST_RESULT:{}:{}", success, message);
                        if let Err(e) = client.command(NetworkCommand::Publish {
                            topic: "test-results".to_string(),
                            data: result_msg.as_bytes().to_vec(),
                        }).await {
                            tracing::error!("Failed to publish test result: {}", e);
                        }
                    }

                    // Exit with appropriate status
                    if success {
                        tracing::info!("Test PASSED: {}", message);
                        // Allow some time for the message to be sent before exiting
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Ok(());
                    } else {
                        tracing::error!("Test FAILED: {}", message);
                        // Allow some time for the message to be sent before exiting
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Err(message.into());
                    }
                }
            }
        }
    }
}

// Helper function to verify a remote peer's plog
async fn verify_remote_plog<KP: KeyManager<bs_peer::Error> + MultiSigner<bs_peer::Error>>(
    bs_peer: Arc<Mutex<DefaultBsPeer<KP>>>,
    peer_id: PeerId,
    completion_tx: tokio::sync::mpsc::Sender<(bool, String)>,
) -> Result<(), String> {
    // Simplified error type
    // Implement retry logic for getting the record from DHT
    let mut attempts = 0;
    let max_attempts = 5;
    let mut delay = Duration::from_millis(500);
    let mut cid_bytes = None;

    // Get the Cid from the DHT with retries
    while attempts < max_attempts {
        let peer = bs_peer.lock().await;
        let client = peer
            .network_client
            .as_ref()
            .expect("No network client available");

        match client.get_record(peer_id.to_bytes()).await {
            Ok(bytes) => {
                cid_bytes = Some(bytes);
                break;
            }
            Err(e) => {
                attempts += 1;
                if attempts >= max_attempts {
                    let msg = format!(
                        "Failed to retrieve DHT record after {} attempts: {}",
                        max_attempts, e
                    );
                    tracing::error!("{}", msg);

                    // Simplified error handling for tests
                    completion_tx
                        .send((false, msg.clone()))
                        .await
                        .expect("Failed to send completion");
                    return Err(msg);
                }

                tracing::warn!(
                    "DHT lookup failed (attempt {}/{}): {}",
                    attempts,
                    max_attempts,
                    e
                );
                drop(peer); // Release the lock before sleep
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }

    // Unwrap the cid_bytes - for tests this is fine
    let cid_bytes = cid_bytes.expect("Failed to retrieve head CID from DHT");

    tracing::info!("Retrieved head CID bytes from DHT: {:?}", cid_bytes);

    let head = multicid::Cid::try_from(cid_bytes.as_slice()).unwrap();

    tracing::info!("Retrieved head CID from DHT: {}", head);

    // Now fetch and verify the entry chain
    let peer = bs_peer.lock().await;

    let entry_chain = match get_entry_chain(&head, &*peer).await {
        Ok(chain) => chain,
        Err(e) => {
            let msg = format!("Failed to get entry chain: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    tracing::info!(
        "Retrieved entry chain with {} entries",
        entry_chain.entries.len()
    );

    // Get the vlad from a plog Entry
    let entry_bytes = match (&*peer).resolve(&entry_chain.foot_cid).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("Failed to resolve foot CID: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    let entry = match Entry::try_from(entry_bytes.as_slice()) {
        Ok(entry) => entry,
        Err(e) => {
            let msg = format!("Failed to parse entry: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    let vlad = entry.vlad();

    let first_lock_cid = vlad.cid();
    let entry_bytes = match (&*peer).resolve(first_lock_cid).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("Failed to resolve first lock CID: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    let maybe_first_lock_script = match Script::try_from(entry_bytes.as_slice()) {
        Ok(script) => script,
        Err(e) => {
            let msg = format!("Failed to parse lock script: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    // Build the plog from our fetched components
    let rebuilt_plog = match provenance_log::log::Builder::new()
        // we'll get this from the DHT record key
        .with_vlad(&vlad)
        // First lock script CID is the second half of the vlad
        .with_first_lock(&maybe_first_lock_script)
        // we get these entries from the network
        .with_entries(&entry_chain.entries)
        // We will have the head from the DHT record value
        .with_head(&head)
        // foot is from the entry_chain
        .with_foot(&entry_chain.foot_cid)
        .try_build()
    {
        Ok(plog) => plog,
        Err(e) => {
            let msg = format!("Failed to build plog: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    };

    // Verify the rebuilt plog
    let mut verification_success = true;
    let verify_iter = &mut rebuilt_plog.verify();

    // the log should also verify
    for ret in verify_iter {
        match ret {
            Ok((count, entry, kvp)) => {
                tracing::debug!("Verified entry: {:#?}", entry);
                tracing::debug!("Verified count: {:#?}", count);
                tracing::debug!("Verified kvp: {:#?}", kvp);
            }
            Err(e) => {
                verification_success = false;
                let msg = format!("Plog verification failed: {:#?}", e);
                tracing::error!("{}", msg);
                completion_tx.send((false, msg.clone())).await.unwrap();
                return Err(msg);
            }
        }
    }

    // running resolve_plog should return the same plog
    match resolve_plog(&vlad, &head, &*peer).await {
        Ok(resolved) => {
            if rebuilt_plog != resolved.log {
                verification_success = false;
                let msg = "Resolved plog does not match rebuilt plog";
                tracing::error!("{}", msg);
                completion_tx.send((false, msg.to_string())).await.unwrap();
                return Err(msg.to_string());
            }
        }
        Err(e) => {
            verification_success = false;
            let msg = format!("Failed to resolve plog: {}", e);
            tracing::error!("{}", msg);
            completion_tx.send((false, msg.clone())).await.unwrap();
            return Err(msg);
        }
    }

    assert!(verification_success, "Plog verification failed");

    // For the success case:
    let success_msg = format!("Successfully verified plog from peer {}", peer_id);
    tracing::info!("{}", success_msg);
    completion_tx
        .send((true, success_msg))
        .await
        .expect("Failed to send completion");

    Ok(())
}

#[derive(rust_embed::RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/static"]
struct StaticFiles;

/// Serve the Multiaddr we are listening on and the host files.
pub(crate) async fn serve(libp2p_transport: Multiaddr) {
    let Some(Protocol::Ip6(_listen_addr)) = libp2p_transport.iter().next() else {
        panic!("Expected 1st protocol to be IP6")
    };

    let server = Router::new()
        .route("/", get(get_index))
        .route("/index.html", get(get_index))
        .route("/:path", get(get_static_file))
        .with_state(Libp2pState {
            endpoint: libp2p_transport.clone(),
        })
        .layer(
            // allow cors
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET]),
        );

    let serve_addr_ipv4 = Ipv4Addr::new(127, 0, 0, 1);

    let addr = SocketAddr::new(serve_addr_ipv4.into(), 8080);

    tracing::info!(url=%format!("http://{addr}"), "Serving client files at url");

    tokio::spawn(async move {
        axum::Server::bind(&addr)
            .serve(server.into_make_service())
            .await
            .unwrap();
    });

    tracing::info!(url=%format!("http://{addr}"), "Opening browser");
}

#[derive(Clone)]
struct Libp2pState {
    endpoint: Multiaddr,
}

/// Serves the index.html file for our client.
///
/// Our server listens on a random UDP port for the WebRTC transport.
/// To allow the client to connect, we replace the `__LIBP2P_ENDPOINT__` placeholder with the actual address.
async fn get_index(
    State(Libp2pState {
        endpoint: libp2p_endpoint,
    }): State<Libp2pState>,
) -> Result<Html<String>, StatusCode> {
    let content = StaticFiles::get("index.html")
        .ok_or(StatusCode::NOT_FOUND)?
        .data;

    let html = std::str::from_utf8(&content)
        .expect("index.html to be valid utf8")
        .replace("__LIBP2P_ENDPOINT__", &libp2p_endpoint.to_string());

    Ok(Html(html))
}

/// Serves the static files generated by `wasm-pack`.
async fn get_static_file(Path(path): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    tracing::debug!(file_path=%path, "Serving static file");

    let content = StaticFiles::get(&path).ok_or(StatusCode::NOT_FOUND)?.data;
    let content_type = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();

    Ok(([(CONTENT_TYPE, content_type)], content))
}

/// A report generated by the test
#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    #[serde(rename = "handshakePlusOneRTTMillis")]
    handshake_plus_one_rtt_millis: f32,
    #[serde(rename = "pingRTTMilllis")]
    ping_rtt_millis: f32,
}
