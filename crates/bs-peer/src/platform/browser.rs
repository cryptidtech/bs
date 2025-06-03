//! browser specific bindings
mod error;
pub use error::Error;

use wasm_bindgen_futures::spawn_local;
mod opfs;
use blockstore::Blockstore;
use bs_p2p::{
    events::{
        api::{self, Client},
        PublicEvent,
    },
    swarm, BehaviourBuilder,
};
use futures::channel::{mpsc, oneshot};
use libp2p::multiaddr::{Multiaddr, Protocol};
use libp2p::PeerId;
pub use opfs::OPFSWrapped;

/// Config for starting
/// - libp2p_endpoints: List of libp2p endpoints to connect to.
/// - base_path: Path to the base directory for the blockstore and other data.
#[derive(Clone, Default)]
pub struct StartConfig {
    // TODO: This native node can dial other native nodes, like BOOTNODES
    pub libp2p_endpoints: Vec<String>,
    pub base_path: Option<std::path::PathBuf>,
}

pub async fn start<B: Blockstore + 'static>(
    tx: mpsc::Sender<PublicEvent>,
    blockstore: B,
    config: StartConfig,
) -> Result<(Client, PeerId), Error> {
    let StartConfig {
        libp2p_endpoints,
        base_path,
    } = config;

    tracing::info!("Spawning swarm. Using multiaddr {:?}", libp2p_endpoints);

    let behaviour_builder = BehaviourBuilder::new(blockstore);

    let swarm = swarm::create(
        |key, relay_behaviour| behaviour_builder.build(key, relay_behaviour),
        base_path,
    )
    .await?;

    let peer_id = *swarm.local_peer_id();

    let (mut network_client, network_events, network_event_loop) = api::new(swarm).await;

    spawn_local(async move {
        let _ = network_event_loop.run().await;
    });

    for endpoint in libp2p_endpoints.iter() {
        let mut remote_address = endpoint.parse::<Multiaddr>()?;

        match network_client.dial(remote_address.clone()).await {
            Ok(_) => {
                tracing::info!("☎️ 🎉 Dialed remote peer at {}", remote_address);
            }
            Err(err) => {
                tracing::warn!("Failed to dial remote peer at {}: {}", remote_address, err);
            }
        }

        // add remote peer_id as explicit peer so we can gossipsub to it with minimal peers available
        if let Some(Protocol::P2p(rpid)) = remote_address.pop() {
            network_client.add_peer(rpid).await?;
            tracing::info!("Added remote peer_id as explicit peer: {:?}", rpid);
        }
    }

    tracing::info!("Running network client loop:");

    let mut client_clone = network_client.clone();
    spawn_local(async move {
        client_clone.run(network_events, tx).await;
    });

    Ok((network_client, peer_id))
}
