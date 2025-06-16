#![cfg(not(target_arch = "wasm32"))]

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Router;
use axum::{http::Method, routing::get};
use bs::config::sync::{KeyManager, MultiSigner};
use bs::resolver_ext::ResolverExt as _;
use bs_p2p::events::api::Libp2pEvent;
use bs_p2p::events::PublicEvent;
use bs_peer::peer::{DefaultBsPeer, Resolver};
use bs_wallets::memory::InMemoryKeyManager;
use futures::StreamExt;
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
use provenance_log::{Entry, Script};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            "interop_tests_native=debug,libp2p_webrtc=info,libp2p_ping=debug,beetswap=trace,bs_p2p=debug,bs_peer=debug,bs=debug",
        )
        .try_init();

    tracing::info!("Starting peerpiper-native TESTS");

    let key_manager = InMemoryKeyManager::<bs_peer::Error>::default();

    // Create a new peer with the default platform blockstore
    let bs_peer = DefaultBsPeer::new(key_manager).await.unwrap();

    // Wrap the peer in Arc<Mutex<>> to safely share between tasks
    let bs_peer = Arc::new(Mutex::new(bs_peer));

    // Create a channel to signal test completion
    let (completion_tx, _completion_rx) = channel::<(bool, String)>(1);

    // Clone the peer for the address waiting task
    let bs_peer_clone = Arc::clone(&bs_peer);

    // Wait for listen address
    let address = tokio::select! {
        addr = async {
            let mut peer = bs_peer_clone.lock().await;
            loop {
                if let Some(PublicEvent::ListenAddr { address, .. }) = peer.events.as_mut().unwrap().next().await {
                    tracing::info!(%address, "RXD Address");
                    break address;
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
    let mut verification_result = None;

    loop {
        tokio::select! {
            evt = async {
                let mut peer = bs_peer.lock().await;
                peer.events.as_mut().unwrap().select_next_some().await
            } => {
                if let PublicEvent::Swarm(Libp2pEvent::PutRecordRequest { source }) = evt {
                    // Handle incoming DHT record requests
                    let completion_tx_clone = completion_tx.clone();
                    let bs_peer_clone = Arc::clone(&bs_peer);

                    match verify_remote_plog(bs_peer_clone, source, completion_tx_clone).await {
                        Ok(_) => {
                            tracing::info!("Verification completed successfully for peer {}", source);
                            verification_result = Some(true);
                            break; // Break the loop on successful verification
                        }
                        Err(e) => {
                            tracing::error!("Verification failed for peer {}: {}", source, e);
                            let _ = completion_tx.send((false, e.to_string())).await;
                            verification_result = Some(false);
                            break; // Also break on failure
                        }
                    }
                } else {
                    tracing::debug!("Received event: {:?}", evt);
                }
            }
        }
    }

    // Add assertion after the loop
    assert!(
        verification_result.unwrap_or(false),
        "Verification should have succeeded"
    );
    Ok(())
}

// Helper function to handle errors uniformly
async fn handle_error<E: std::fmt::Display>(
    error: E,
    message_prefix: &str,
    completion_tx: &Sender<(bool, String)>,
) -> Result<(), String> {
    let msg = format!("{}: {}", message_prefix, error);
    tracing::error!("{}", msg);
    completion_tx.send((false, msg.clone())).await.unwrap();
    Err(msg)
}

// Helper function to verify a remote peer's plog
async fn verify_remote_plog<KP: KeyManager<bs_peer::Error> + MultiSigner<bs_peer::Error> + Sync>(
    bs_peer: Arc<Mutex<DefaultBsPeer<KP>>>,
    peer_id: PeerId,
    completion_tx: tokio::sync::mpsc::Sender<(bool, String)>,
) -> Result<(), String> {
    tracing::info!("1/ Starting verification for peer: {}", peer_id);

    tokio::time::sleep(Duration::from_secs(4)).await;

    // get bytes from KAd DHT record
    let cid_bytes = {
        let mut lock = bs_peer.lock().await;
        let network_client = lock.network_client.as_mut().ok_or_else(|| {
            tracing::error!("Network client is not initialized");
            "Network client is not initialized".to_string()
        })?;
        network_client
            .get_record(peer_id.into())
            .await
            .map_err(|e| {
                tracing::error!("Failed to get DHT record: {}", e);
                format!("Failed to get DHT record: {}", e)
            })?
    };

    tracing::info!("2/ Retrieved plog head bytes: {:?}", cid_bytes);

    let head = match multicid::Cid::try_from(cid_bytes.as_slice()) {
        Ok(cid) => cid,
        Err(e) => {
            return handle_error(
                format!("Failed to parse CID from bytes: {}", e),
                "CID parse error",
                &completion_tx,
            )
            .await;
        }
    };

    tracing::info!("3/ Retrieved plog head: {}", head);

    // Now fetch and verify the entry chain
    let entry_chain = {
        let peer = bs_peer.lock().await;
        (&*peer).get_entry_chain(&head).await.map_err(|e| {
            tracing::error!("Failed to get entry chain: {}", e);
            e.to_string()
        })?
    };

    tracing::info!(
        "4/ Retrieved entry chain with {} entries",
        entry_chain.entries.len()
    );

    let entry = if entry_chain.entries.len() == 1 {
        // For a single entry chain, head and foot are the same, so we can use
        // the head bytes we already fetched when building the entry_chain
        tracing::info!("Single entry chain - head and foot are the same");
        entry_chain.foot().cloned().unwrap()
    } else {
        // For multiple entries, resolve the foot separately
        tracing::info!("Multiple entries - resolving foot CID");
        let entry_bytes = {
            let peer = bs_peer.lock().await;
            (&*peer).resolve(&entry_chain.foot_cid).await.map_err(|e| {
                tracing::error!("Failed to resolve foot CID: {}", e);
                e.to_string()
            })?
        };

        tracing::info!("Foot resolved. Converting to Entry...");
        match Entry::try_from(entry_bytes.as_slice()) {
            Ok(entry) => entry,
            Err(e) => {
                tracing::error!("Failed to parse entry: {}", e);
                return handle_error(e, "Failed to parse entry", &completion_tx).await;
            }
        }
    };

    let vlad = entry.vlad();

    let first_lock_cid = vlad.cid();

    tracing::info!("5/ First lock CID: {}", first_lock_cid);

    // We store the first lock bytes under /vlad/cid key in the Entry kvp
    // iter ove rentry.ops() until match on Update(Key, Value) where Key is /vlad/cid
    let provenance_log::Value::Data(first_lock_bytes) = entry
        .ops()
        .find_map(|op| {
            if let provenance_log::Op::Update(key, value) = op {
                if key.as_str() == "/vlad/data" {
                    return Some(value);
                }
            }
            None
        })
        .ok_or_else(|| {
            tracing::error!("No first lock CID found in entry");
            "No first lock CID found in entry".to_string()
        })?
    else {
        return handle_error(
            "First lock CID not found in entry",
            "Entry parsing error",
            &completion_tx,
        )
        .await;
    };

    tracing::debug!("6/ First lock bytes: {:?}", first_lock_bytes);

    let first_lock_script = match Script::try_from(first_lock_bytes.as_slice()) {
        Ok(script) => script,
        Err(e) => {
            return handle_error(e, "Failed to parse lock script", &completion_tx).await;
        }
    };

    tracing::debug!("7/ First lock script built Rebuilt plog");

    // Build the plog from our fetched components
    let rebuilt_plog = match provenance_log::log::Builder::new()
        // we'll get this from the DHT record key
        .with_vlad(&vlad)
        // First lock script CID is the second half of the vlad
        .with_first_lock(&first_lock_script)
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
            return handle_error(e, "Failed to build plog", &completion_tx).await;
        }
    };

    tracing::info!("8/ Rebuilt plog successfully");

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
                return handle_error(e, "Plog verification failed", &completion_tx).await;
            }
        }
    }

    // running resolve_plog should return the same plog
    let resolved_plog = {
        let peer = bs_peer.lock().await;
        (&*peer).resolve_plog(&head).await.map_err(|e| {
            verification_success = false;
            format!("Failed to resolve plog: {}", e)
        })?
    };

    if rebuilt_plog != resolved_plog.log {
        verification_success = false;
        return handle_error(
            "Resolved plog does not match rebuilt plog",
            "",
            &completion_tx,
        )
        .await;
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

async fn retry_with_timeout<F, Fut, T, E>(
    mut operation: F,
    max_attempts: usize,
    timeout_duration: Duration,
    retry_delay: Duration,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut attempts = 0;

    loop {
        attempts += 1;

        // Try the operation with timeout
        let result = tokio::time::timeout(timeout_duration, operation()).await;

        match result {
            Ok(Ok(value)) => return Ok(value), // Success
            Ok(Err(e)) => {
                if attempts >= max_attempts {
                    return Err(RetryError::MaxAttemptsReached(e));
                }
                println!("Attempt {} failed: {:?}, retrying...", attempts, e);
            }
            Err(_) => {
                if attempts >= max_attempts {
                    return Err(RetryError::Timeout);
                }
                println!("Attempt {} timed out, retrying...", attempts);
            }
        }

        // Wait before retrying (except on last attempt)
        if attempts < max_attempts {
            tokio::time::sleep(retry_delay).await;
        }
    }
}

#[derive(Debug)]
enum RetryError<E> {
    MaxAttemptsReached(E),
    Timeout,
}
