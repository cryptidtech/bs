//! Native specific code
mod native_blockstore;
use bs_p2p::{
    events::{
        api::{self, Client},
        PublicEvent,
    },
    swarm, BehaviourBuilder,
};
pub use native_blockstore::NativeBlockstore;

mod error;
pub use error::NativeError;

use blockstore::Blockstore;
use futures::channel::{mpsc, oneshot};
use libp2p::{
    multiaddr::{Multiaddr, Protocol},
    PeerId,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::spawn;

use crate::Error;

/// Config for starting the network.
/// - libp2p_endpoints: List of libp2p endpoints to connect to.
/// - base_path: Path to the base directory for the blockstore and other data.
#[derive(Clone, Default)]
pub struct StartConfig {
    // TODO: This native node can dial other native nodes, like BOOTNODES
    pub libp2p_endpoints: Vec<String>,
    pub base_path: Option<std::path::PathBuf>,
}

/// Create the swarm, and get handles to control it.
/// Any protocols that are passed will be updated with the incoming streams.
pub async fn start<B: Blockstore + 'static>(
    tx: mpsc::Sender<PublicEvent>,
    blockstore: B,
    config: StartConfig,
) -> Result<(Client, PeerId), NativeError> {
    let StartConfig {
        libp2p_endpoints: _,
        base_path,
    } = config;

    let behaviour_builder = BehaviourBuilder::new(blockstore);

    let mut swarm = swarm::create(
        |key, relay_behaviour| behaviour_builder.build(key, relay_behaviour),
        base_path,
    )
    .await?;

    let peer_id = *swarm.local_peer_id();

    swarm
        .behaviour_mut()
        .kad
        .set_mode(Some(libp2p::kad::Mode::Server));

    let peer_id = *swarm.local_peer_id();
    tracing::info!("Local peer id: {:?}", peer_id);

    let (mut network_client, network_events, network_event_loop) = api::new(swarm).await;

    // We need to start the network event loop first in order to listen for our address
    tokio::spawn(async move {
        if let Err(e) = network_event_loop.run().await {
            tracing::error!("Network event loop failed: {}", e);
        }
    });

    let address_webrtc = Multiaddr::from(Ipv6Addr::UNSPECIFIED)
        .with(Protocol::Udp(0))
        .with(Protocol::WebRTCDirect);

    let addr_webrtc_ipv4 = Multiaddr::from(Ipv4Addr::UNSPECIFIED)
        .with(Protocol::Udp(0))
        .with(Protocol::WebRTCDirect);

    for addr in [
        address_webrtc,
        addr_webrtc_ipv4,
        // address_quic, address_tcp
    ] {
        tracing::info!("Listening on {:?}", addr.clone());
        network_client.start_listening(addr).await?;
    }

    // for peer in &BOOTNODES {
    //     let addr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?
    //         .with(Protocol::P2p(libp2p::PeerId::from_str(peer)?));
    //     network_client.dial(addr).await?;
    // }

    let mut client_clone = network_client.clone();

    tokio::spawn(async move {
        client_clone.run(network_events, tx).await;
    });

    Ok((network_client, peer_id))
}
