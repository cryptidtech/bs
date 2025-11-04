//! Headless peer designed to run without a UI, suitable for server environments.
use anyhow::Result;
use axum::{extract::State, routing::get, Json, Router};
use bs_p2p::events::{api::Libp2pEvent, Client, PublicEvent};
use bs_peer::platform::{start, Blockstore, StartConfig};
use futures::{channel::mpsc, StreamExt as _};
use libp2p::PeerId;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    // tracing_subscriber::fmt()
    //     .with_env_filter(EnvFilter::from_default_env())
    //    .init();
    // set bs_server=info
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("bs_server=info"))
        .with_file(true)
        .with_line_number(true)
        .init();

    info!("Starting bs-server headless peer...");

    // Configuration (could come from command line args or config file)
    let config = parse_config()?;
    let base_path = config.data_dir.unwrap_or_else(|| {
        directories::ProjectDirs::from("org", "bettersign", "superpeer")
            .map(|proj_dirs| proj_dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("./.bs-server"))
    });

    // Create blockstore
    let blockstore = Blockstore::new(base_path.clone()).await?;

    // Create channel for p2p events
    let (tx, rx) = mpsc::channel::<PublicEvent>(32);

    // Start the peer
    let start_config = StartConfig {
        libp2p_endpoints: config.bootstrap_peers,
        base_path: Some(base_path),
    };

    let (client, peer_id) = match start(tx, blockstore, start_config).await {
        Ok((client, peer_id)) => {
            info!("Peer started with ID: {peer_id}");
            (client, peer_id)
        }
        Err(e) => {
            error!("Failed to start peer: {e}");
            return Err(e.into());
        }
    };

    // Start API server if configured
    if let Some(api_port) = config.api_port {
        spawn_api_server(api_port, client.clone(), peer_id).await?;
    }

    // Process events from the network
    tokio::spawn(handle_network_events(rx));

    // Wait for termination signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal. Shutting down gracefully...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    info!("Server stopped.");
    Ok(())
}

/// Server configuration
struct ServerConfig {
    bootstrap_peers: Vec<String>,
    data_dir: Option<PathBuf>,
    api_port: Option<u16>,
}

fn parse_config() -> Result<ServerConfig> {
    // Could use clap or config crate for more sophisticated config
    // This is a simple example
    Ok(ServerConfig {
        bootstrap_peers: vec![],
        data_dir: None,
        api_port: Some(8000),
    })
}

// Wrap the client in Arc for sharing between handlers
struct ApiState {
    client: Client,
    peer_id: PeerId,
}

async fn spawn_api_server(port: u16, client: Client, peer_id: PeerId) -> Result<()> {
    let state = Arc::new(ApiState { client, peer_id });

    // Build API routes
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/info", get(get_peer_info))
        // Add more routes as needed
        .with_state(state);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("API server listening on {addr}");

    tokio::spawn(async move {
        // Create a TCP listener
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        // Use the new axum::serve function to serve the application
        if let Err(e) = axum::serve(listener, app).await {
            error!("API server error: {e}");
        }
    });

    Ok(())
}

async fn get_peer_info(State(state): State<Arc<ApiState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "peer_id": state.peer_id.to_string(),
        // TODO: Add more peer info
    }))
}

async fn handle_network_events(mut rx: mpsc::Receiver<PublicEvent>) {
    while let Some(event) = rx.next().await {
        match event {
            PublicEvent::Connected => {
                info!("Peer connected");
            }
            PublicEvent::ConnectionClosed { peer, cause } => {
                info!("Peer disconnected: {peer}, cause: {cause}");
            }
            PublicEvent::Swarm(Libp2pEvent::PutRecordRequest { source }) => {}
            _ => {}
        }
    }
}
