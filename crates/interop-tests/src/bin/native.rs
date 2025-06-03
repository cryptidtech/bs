#![cfg(not(target_arch = "wasm32"))]

use bs_p2p::events::PublicEvent;
use bs_peer::peer::{get_entry_chain, resolve_plog, DefaultBsPeer, Resolver};
use bs_wallets::memory::InMemoryKeyManager;
use provenance_log::{Entry, Script};

use std::str::FromStr;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Router;
use axum::{http::Method, routing::get};
use futures::channel::{mpsc, oneshot};
use futures::StreamExt;
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
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
    let mut bs_peer = DefaultBsPeer::new(key_manager).await?;

    let address = loop {
        if let PublicEvent::ListenAddr { address, .. } =
            bs_peer.events.as_mut().unwrap().next().await.unwrap()
        {
            tracing::info!(%address, "RXD Address");
            break address;
        }
    };
    // Serve .wasm, .js and server multiaddress over HTTP on this address.
    tokio::spawn(serve(address.clone()));

    loop {
        tokio::select! {
            msg = bs_peer.events.as_mut().unwrap().select_next_some() => {
                tracing::info!("Received msg: {:?}", msg);
                match msg {
                    PublicEvent::NewConnection { peer } => {
                       // Once connection establish, subscribe to "test" topic
                        tracing::info!("New connection from {}", peer);

                        let p = PeerId::from_str(&peer).unwrap();

                        // get the Cid from the DHT
                        let Some(client) = &bs_peer.network_client.as_ref() else {
                            tracing::error!("No network client available");
                            continue;
                        };
                        let cid_bytes = client.get_record(p.to_bytes()).await?;
                        let head = multicid::Cid::try_from(cid_bytes.as_slice()).unwrap();

                        let entry_chain = get_entry_chain(&head, &bs_peer).await?;

                        // Reconstruct the plog from the fetched entries
                        // Get the vlad from a plog Entry
                        let entry_bytes = (&bs_peer).resolve(&entry_chain.foot_cid).await?;
                        let entry = Entry::try_from(entry_bytes.as_slice()).unwrap();
                        let vlad = entry.vlad();

                        let first_lock_cid = vlad.cid();
                        let entry_bytes = (&bs_peer).resolve(first_lock_cid).await?;
                        let maybe_first_lock_script = Script::try_from(entry_bytes.as_slice())?;

                        let rebuilt_plog = provenance_log::log::Builder::new()
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
                            .try_build()?;


                        let verify_iter = &mut rebuilt_plog.verify();

                        // the log should also verify
                        for ret in verify_iter {
                            match ret {
                                Ok((count, entry, kvp)) => {
                                    tracing::trace!("Verified entry: {:#?}", entry);
                                    tracing::trace!("Verified count: {:#?}", count);
                                    tracing::trace!("Verified kvp: {:#?}", kvp);
                                }
                                Err(e) => {
                                    tracing::error!("Error: {:#?}", e);
                                    // fail test
                                    panic!("Error in log verification");
                                }
                            }
                        }
                        // running resolve_plog should return the same plog
                        let resolved = resolve_plog(&vlad, &head, &bs_peer).await?;
                        assert_eq!(rebuilt_plog, resolved.log);

                    }
                    PublicEvent::Message { peer, topic, data } => {
                        tracing::info!("Received message from {} on topic {}: {:?}", peer, topic, data);
                    }
                    PublicEvent::Pong { peer, rtt } => {
                        tracing::info!("Received pong from {} with rtt: {}", peer, rtt);
                    }
                    _ => {}
                }
            }
            // _ = tokio::signal::ctrl_c() => {
            //     tracing::info!("Received ctrl-c");
            //     break;
            // }
        }
    }
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

    // let (results_tx, mut results_rx) = mpsc::channel(1);

    let server = Router::new()
        .route("/", get(get_index))
        .route("/index.html", get(get_index))
        .route("/:path", get(get_static_file))
        // Report tests status
        // .route("/results", post(post_results))
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
    //
    // let (mut chrome, driver) = open_in_browser(&format!("http://{addr:?}"))
    //     .await
    //     .map_err(|e| tracing::error!(?e, "Failed to open browser"))
    //     .unwrap();
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
