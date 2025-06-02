//! The Events API for interacting witht he netowrk events. 
use crate::events::delay;
pub use crate::behaviour::req_res::{PeerRequest, PeerResponse};
use libp2p::Multiaddr;
use crate::events::{NetworkError, PublicEvent};
use crate::behaviour::{Behaviour, BehaviourEvent};
use crate::Error;
use blockstore::Blockstore;
use futures::stream::StreamExt;
use futures::{
    channel::{
        mpsc::{self, Receiver},
        oneshot,
    },
    SinkExt,
};
use libp2p::core::transport::ListenerId;
use libp2p::kad::store::RecordStore;
use libp2p::kad::PeerRecord;
use libp2p::kad::{InboundRequest, Record};
pub use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identify, kad, ping, PeerId, StreamProtocol};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use web_time::Instant;

const TICK_INTERVAL: Duration = Duration::from_secs(15);

/// Create new API to interact with the network:
///
/// - Network Client: Interact with the netowrk by sending
/// - Network Event Loop: Start the network event loop
pub async fn new<B: Blockstore + 'static>(
    swarm: Swarm<Behaviour<B>>,
) -> (Client, Receiver<PublicEvent>, EventLoop<B>) {
    // These command senders/recvr are used to pass along parsed generic commands to the network event loop
    let (command_sender, command_receiver) = tokio::sync::mpsc::channel(32);
    let (event_sender, event_receiver) = mpsc::channel(32);

    (
        Client { command_sender },
        event_receiver,
        EventLoop::new(swarm, command_receiver, event_sender),
    )
}

/// This client is used to send [Command]s to the network event loop
#[derive(Clone, Debug)]
pub struct Client {
    command_sender: tokio::sync::mpsc::Sender<NetworkCommand>,
}

impl Client {
    /// Listen for incoming connections on the given address.
    pub async fn start_listening(&mut self, addr: Multiaddr) -> Result<ListenerId, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(NetworkCommand::StartListening { addr, sender })
            .await?;
        receiver.await?
    }
    /// Dial the given addresses
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(NetworkCommand::Dial { addr, sender })
            .await?;
        receiver.await?
    }

    /// Request a response from a PeerId
    pub async fn request_response(&self, request: Vec<u8>, peer: PeerId) -> Result<Vec<u8>, Error> {
        tracing::trace!("Sending request to {peer}");
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .command_sender
            .send(NetworkCommand::Jeeves {
                request,
                peer,
                sender,
            })
            .await
        {
            tracing::error!("Failed to send request response command: {:?}", e);
        }

        receiver.await.map_err(Error::OneshotCanceled)?
    }
    /// Respond with a file to a request
    pub async fn respond_bytes(
        &mut self,
        bytes: Vec<u8>,
        channel: ResponseChannel<PeerResponse>,
    ) -> Result<(), Error> {
        Ok(self
            .command_sender
            .send(NetworkCommand::RespondJeeves { bytes, channel })
            .await?)
    }

    /// Request bits via Bitswap
    pub async fn get_bits(&self, cid: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(NetworkCommand::BitswapQuery { cid, sender })
            .await?;
        tracing::info!("Awaiting bitswap query response");
        // TODO: Add timeout
        Ok(receiver.await?)
    }

    /// Get a record from the DHT given the key
    pub(crate) async fn get_providers(&self, key: Vec<u8>) -> Result<HashSet<PeerId>, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(NetworkCommand::GetProviders { key, sender })
            .await?;
        receiver.await.map_err(Error::OneshotCanceled)
    }

    /// Gets a record from the DHT
    pub(crate) async fn get_record(&self, key: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(NetworkCommand::GetRecord { key, sender })
            .await?;
        receiver.await.map_err(Error::OneshotCanceled)
    }

    /// Add a peer to the routing table
    pub async fn add_peer(&mut self, peer_id: PeerId) -> Result<(), Error> {
        Ok(self
            .command_sender
            .send(NetworkCommand::AddPeer { peer_id })
            .await?)
    }
    pub async fn publish(&mut self, message: impl AsRef<[u8]>, topic: String) -> Result<(), Error> {
        Ok(self
            .command_sender
            .send(NetworkCommand::Publish {
                data: message.as_ref().to_vec(),
                topic,
            })
            .await?)
    }
    pub async fn subscribe(&mut self, topic: String) -> Result<(), Error> {
        Ok(self
            .command_sender
            .send(NetworkCommand::Subscribe { topic })
            .await?)
    }

    /// General command PeerPiperCommand parsed into Command then called
    pub async fn command(&mut self, command: NetworkCommand) -> Result<(), Error> {
        Ok(self.command_sender.send(command).await?)
    }
    /// Run the Client loop, awaiting commands and passing along network events.
    // Loop awaits two separate futures using select:
    // 1) Network_events.select_next_some()
    // 2) Recieved Network Commands via `command_receiver`, passing along PeerPiperCommand to network_client.command(pp_cmd)
    pub async fn run(
        &mut self,
        mut network_events: Receiver<PublicEvent>,
        mut tx: mpsc::Sender<PublicEvent>,
    ) {
        tracing::info!("🚀 Starting network client loop");
        loop {
            tokio::select! {
                event = network_events.next() => {
                    let Some(event) = event else {
                        tracing::warn!("⛔ Network event channel closed, shutting down network event loop");
                        break;
                    };
                    tracing::debug!("Network event: {:?}", event);
                    if let Err(network_event) = tx.send(event).await {
                        tracing::error!("Failed to send swarm event: {:?}", network_event);
                        // break;
                        continue;
                    }
                },
            }
        }
    }
}

/// PeerPiper Network Commands (Libp2p)
#[derive(Debug)]
pub enum NetworkCommand {
    StartListening {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<ListenerId, Error>>,
    },
    Dial {
        addr: Multiaddr,
        sender: oneshot::Sender<Result<(), Error>>,
    },
    Publish {
        data: Vec<u8>,
        topic: String,
    },
    Subscribe {
        topic: String,
    },
    Unsubscribe {
        topic: String,
    },
    AddPeer {
        peer_id: PeerId,
    },
    ShareMultiaddr,
    /// Jeeves RequestResponse. Ask a String from a PeerId.
    Jeeves {
        request: Vec<u8>,
        peer: PeerId,
        sender: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Jeeves Response
    RespondJeeves {
        bytes: Vec<u8>,
        channel: ResponseChannel<PeerResponse>,
    },
    /// Puts a Record on the DHT
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Get a record from the DHT
    GetRecord {
        key: Vec<u8>,
        sender: oneshot::Sender<Vec<u8>>,
    },
    /// Get a record from the DHT
    GetProviders {
        key: Vec<u8>,
        sender: oneshot::Sender<HashSet<PeerId>>,
    },
    /// Start providing a key on the DHT
    StartProviding {
        key: Vec<u8>,
    },
    /// Bitswap Query
    BitswapQuery {
        cid: Vec<u8>,
        sender: oneshot::Sender<Vec<u8>>,
    },
}

/// Inner Libp2p Events which cannot be serialized
pub enum Libp2pEvent {
    /// The unique Event to this api file that never leaves; all other events propagate out
    InboundRequest {
        request: PeerRequest,
        channel: ResponseChannel<PeerResponse>,
    },
    /// DHT Provider Request for when someone asks for a record
    DhtProviderRequest {
        key: Vec<u8>,
        channel: ResponseChannel<Vec<u8>>,
    },
    /// An inbound request to Put a Record into the DHT from a source PeerId
    PutRecordRequest { source: PeerId, record: Record },
    /// A Stream we wanted opened is now open
    StreamOpened {
        stream_protocol: StreamProtocol,
        stream: libp2p::Stream,
        peer_id: PeerId,
    },
}

impl std::fmt::Debug for Libp2pEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Libp2pEvent::InboundRequest { request, channel } => f
                .debug_struct("InboundRequest")
                .field("request", request)
                .field("channel", channel)
                .finish(),
            Libp2pEvent::DhtProviderRequest { key, channel } => f
                .debug_struct("DhtProviderRequest")
                .field("key", key)
                .field("channel", channel)
                .finish(),
            Libp2pEvent::PutRecordRequest { source, record } => f
                .debug_struct("PutRecordRequest")
                .field("source", source)
                .field("record", record)
                .finish(),
            Libp2pEvent::StreamOpened {
                stream_protocol,
                peer_id,
                ..
            } => f
                .debug_struct("StreamOpened")
                .field("protocol", stream_protocol)
                .field("peer_id", peer_id)
                .finish(),
        }
    }
}

/// The network event loop.
/// Handles all the network logic for us.
pub struct EventLoop<B: Blockstore + 'static> {
    /// A future that fires at a regular interval and drives the behaviour of the network.
    tick: delay::Delay,
    /// The libp2p Swarm that handles all the network logic for us.
    swarm: Swarm<Behaviour<B>>,
    /// Channel to send commands to the network event loop.
    command_receiver: tokio::sync::mpsc::Receiver<NetworkCommand>,
    /// Channel to send events from the network event loop to the user.
    event_sender: mpsc::Sender<PublicEvent>,
    /// Jeeeves Tracking
    pending_requests: HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<u8>, Error>>>,

    /// GetProviders tracking
    pending_get_providers: HashMap<kad::QueryId, oneshot::Sender<HashSet<PeerId>>>,

    /// pending bitswap queries
    pending_queries: HashMap<beetswap::QueryId, oneshot::Sender<Vec<u8>>>,

    /// Pending Get Records from DHT
    pending_get_records: HashMap<kad::QueryId, oneshot::Sender<Vec<u8>>>,
}

impl<B: Blockstore> EventLoop<B> {
    /// Creates a new network event loop.
    fn new(
        swarm: Swarm<Behaviour<B>>,
        command_receiver: tokio::sync::mpsc::Receiver<NetworkCommand>,
        event_sender: mpsc::Sender<PublicEvent>,
    ) -> Self {
        Self {
            tick: delay::Delay::new(TICK_INTERVAL),
            swarm,
            command_receiver,
            event_sender,
            pending_requests: HashMap::new(),
            pending_get_providers: Default::default(),
            pending_queries: Default::default(),
            pending_get_records: Default::default(),
        }
    }

    /// Runs the network event loop.
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite.")).await?,
                command = self.command_receiver.recv() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None => return Ok(()),
                },
                _ = &mut self.tick => self.handle_tick().await,
            }
        }
    }

    /// Handles a tick of the `tick` future.
    async fn handle_tick(&mut self) {
        tracing::info!("🕒 Tick");
        self.tick.reset(TICK_INTERVAL);

        // Also show all kad records from kad store
        let records = self.swarm.behaviour_mut().kad.store_mut().records();

        if records.clone().count() == 0 {
            tracing::debug!("Kad store is empty");
        }

        records.into_iter().for_each(|record| {
            tracing::debug!(
                "Kad Key: {:?} \n\n Value: {:?}",
                record.key.to_vec(),
                record.value
            );
        });

        // clone the records
        let records = self
            .swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .records()
            .map(|mut r| r.to_mut().clone())
            .collect::<Vec<_>>();

        for record in records {
            let quorum = kad::Quorum::One;

            if let Some(expires) = record.expires {
                if expires < Instant::now() + Duration::from_secs(60) {
                    let expires = Some(Instant::now() + Duration::from_secs(22 * 60 * 60));
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .kad
                        .put_record(Record { expires, ..record }, quorum)
                    {
                        tracing::error!("Failed to put record: {e}");
                    }
                }
            }
        }

        // if let Some(Err(e)) = self
        //     .swarm
        //     .behaviour_mut()
        //     .kademlia
        //     .as_mut()
        //     .map(|k| k.bootstrap())
        // {
        //     tracing::debug!("Failed to run Kademlia bootstrap: {e:?}");
        // }

        let _message = "Hello world! Sent from the rust-peer".to_string();

        // if let Some(Err(err)) = self
        //     .swarm
        //     .behaviour_mut()
        //     .gossipsub
        //     .as_mut()
        //     .map(|g| g.publish(topic::topic(), message.as_bytes()))
        // {
        //     error!("Failed to publish periodic message: {err}")
        // }
    }

    /// Handles a network event according to the matched Event type
    async fn handle_event(&mut self, event: SwarmEvent<BehaviourEvent<B>>) -> Result<(), Error> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("🌐  New address: {address}");
                let mut addr_handler = || {
                    let p2p_addr = address
                        .clone()
                        .with(Protocol::P2p(*self.swarm.local_peer_id()));

                    // info!("Listen p2p address: \n\x1b[30;1;42m{p2p_addr}\x1b[0m");
                    // This address is reachable, add it
                    self.swarm.add_external_address(p2p_addr.clone());

                    // check off adding this address
                    tracing::info!("👉  Added {p2p_addr}");

                    // pass the address back to the other task, for display, etc.
                    self.event_sender
                        .try_send(PublicEvent::ListenAddr {
                            address: p2p_addr,
                        })
                };
                // Protocol::Ip is the first item in the address vector
                match address.iter().next() {
                    Some(Protocol::Ip6(ip6)) => {
                        // Only add our globally available IPv6 addresses to the external addresses list.
                        if !ip6.is_loopback()
                            && !ip6.is_unspecified() 
                            && !ip6.is_multicast()
                            && (ip6.segments()[0] & 0xffc0) != 0xfe80 // no fe80::/10 addresses, (!ip6.is_unicast_link_local() requires nightly)
                            && (ip6.segments()[0] & 0xfe00) != 0xfc00 // Unique Local Addresses (ULAs, fd00::/8) are private IPv6 addresses and should not be advertised.
                        {
                            addr_handler()?;
                        }
                    }
                    Some(Protocol::Ip4(ip4)) => {
                        if !(ip4.is_loopback() || ip4.is_unspecified() || ip4.is_private() || ip4.is_multicast() || ip4 == Ipv4Addr::LOCALHOST || ip4.octets()[0] & 240 == 240 && !ip4.is_broadcast())
                        {
                            addr_handler()?;
                        }
                    }
                    _ => {
                        tracing::warn!("Unknown address type: {address}");
                    }
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                //endpoint: ConnectedPoint::Listener { send_back_addr, .. },
                established_in,
                ..
            } => {
                tracing::info!("✔️  Connection Established to {peer_id} in {established_in:?}");
                // add as explitcit peer
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer_id);

                if let Err(e) = self
                    .event_sender
                    .send(PublicEvent::NewConnection {
                        peer: peer_id.to_string(),
                    })
                    .await
                {
                    tracing::error!("Failed to send NewConnection event: {e}");
                    return Err(Error::SendFailure("Failed to send NewConnection event".to_string()));
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!("Failed to dial {peer_id:?}: {error}");

                match (peer_id, &error) {
                    (Some(_peer_id), libp2p::swarm::DialError::Transport(details_vector)) => {
                        for (addr, _error) in details_vector.iter() {
                            // self.swarm
                            //     .behaviour_mut()
                            //     .kademlia
                            //     .as_mut()
                            //     .map(|k| k.remove_address(&peer_id, addr));
                            //
                            // self.swarm.remove_external_address(addr);

                            tracing::debug!("Removed ADDR {addr:?} from the routing table (if it was in there).");
                        }
                    }
                    _ => {
                        tracing::warn!("{error}");
                        return Err(Error::StaticStr("Failed to dial peer"));
                    }
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::info!("Connection to {peer_id} closed: {cause:?}");
                // send an event
                self.event_sender
                    .send(PublicEvent::ConnectionClosed {
                        peer: peer_id.to_string(),
                        // unwrap cause if is Some, otherwise return "Unknown cause"
                        cause: cause
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "Unknown cause".to_string()),
                    })
                    .await?;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                peer,
                result: Ok(rtt),
                ..
            })) => {
                tracing::info!("🏓 Ping {peer} in {rtt:?}");
                // send msg
                self.event_sender
                    .send(PublicEvent::Pong {
                        peer: peer.to_string(),
                        rtt: rtt.as_millis() as u64,
                    })
                    .await?;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                peer,
                result: Err(err),
                connection,
            })) => {
                tracing::warn!("⚠️  Ping {peer} failed: {err}");
                self.swarm.behaviour_mut().kad.remove_peer(&peer);
                let found = self.swarm.close_connection(connection);
                tracing::warn!("Connection closed: {found}");
            }
            // SwarmEvent::Behaviour(BehaviourEvent::Relay(e)) => {
            //     tracing::debug!("{:?}", e);
            // }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Message {
                    message_id: _,
                    propagation_source: peer_id,
                    message,
                },
            )) => {
                tracing::info!("📨 Received message from {:?}", message.source);

                self.event_sender
                    .send(PublicEvent::Message {
                        peer: peer_id.to_string(),
                        topic: message.topic.to_string(),
                        data: message.data,
                    })
                    .await?;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Subscribed { peer_id, topic },
            )) => {
                tracing::debug!("{peer_id} subscribed to {topic}");

                // Indiscriminately add the peer to the routing table
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer_id);

                // publish a message
                // get the last 4 chars of the peer_id as slice:
                let message = format!(
                    "📨 Welcome subscriber ..{} of topic {:?}! 🎉",
                    &peer_id.to_string()[peer_id.to_string().len() - 4..],
                    topic
                );

                // subscribe to this topic so we can act as super peer to browsers
                if let Err(err) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&libp2p::gossipsub::IdentTopic::new(topic.as_str()))
                {
                    tracing::error!("Failed to subscribe to topic: {err}");
                }

                if let Err(err) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, message.as_bytes())
                {
                    tracing::error!("Failed to publish welcome message: {err}");
                    return Err(Error::StaticStr("Failed to publish welcome message"));
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::PeerRequest(
                request_response::Event::Message { message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel: _, ..
                } => {
                    tracing::trace!("Received request: {:?}", &request);

                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => self
                    .pending_requests
                    .remove(&request_id)
                    .ok_or(Error::StaticStr("Remove failed"))?
                    .send(Ok(response.to_vec()))
                    .map_err(|_| Error::StaticStr("Failed to send response"))?,
            },
            SwarmEvent::Behaviour(BehaviourEvent::PeerRequest(
                request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    peer,
                    ..
                },
            )) => {
                tracing::error!(
                    "Request failed, couldn't SEND JEEVES to peer {peer}: {error} on request_id: {request_id}"
                );
                self.pending_requests
                    .remove(&request_id)
                    .ok_or(Error::StaticStr("Remove failed"))?
                    .send(Err(Error::OutboundFailure(error)))
                    .map_err(|_| Error::StaticStr("Failed to send response"))?;
            }
            // SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Error {
            //     peer_id,
            //     error: libp2p::swarm::StreamUpgradeError::Timeout,
            // })) => {
            //     debug!("Identify Error to {peer_id} closed due to timeout");
            //
            //     // When a browser tab closes, we don't get a swarm event
            //     // maybe there's a way to get this with TransportEvent
            //     // but for now remove the peer from routing table if there's an Identify timeout
            //
            //     // Add a warning counter, kick off after 3 tries to Identify
            //     // if the peer is still in the routing table, remove it
            //     let warning_count = self.warning_counters.entry(peer_id).or_insert(0);
            //     *warning_count += 1;
            //
            //     debug!("⚠️  Identify count Warning for {peer_id}: {warning_count}");
            //
            //     // Remove peer after 3 non responses to Identify
            //     if *warning_count >= 3 {
            //         // remove the peer from the Kad routing table
            //         self.swarm
            //             .behaviour_mut()
            //             .kademlia
            //             .as_mut()
            //             .map(|k| k.remove_peer(&peer_id));
            //
            //         // remove from Gossipsub
            //         if let Some(g) = self.swarm.behaviour_mut().gossipsub.as_mut() {
            //             g.remove_explicit_peer(&peer_id)
            //         };
            //
            //         // remove from swarm. TODO: rm unwrap
            //         // self.swarm.disconnect_peer_id(peer_id).unwrap();
            //
            //         // remove the peer from the warning_counters HashMap
            //         self.warning_counters.remove(&peer_id);
            //         debug!("Removed PEER {peer_id} from the routing table (if it was in there).");
            //     }
            // }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info:
                    identify::Info {
                        listen_addrs,
                        protocols,
                        observed_addr,
                        ..
                    },
                ..
            })) => {
                tracing::debug!(
                    "ℹ️  identify Received peer {} observed_addr: {}",
                    peer_id,
                    observed_addr
                );

                // remove warning_counters entry for this peer if it exists
                //self.warning_counters.remove(&peer_id);

                // Only add the address to the matching protocol name,
                if protocols.iter().any(|p| {
                    self.swarm
                        .behaviour()
                        .kad
                        .protocol_names()
                        .iter()
                        .any(|q| p == q)
                }) {
                    for addr in listen_addrs {
                        tracing::debug!("ℹ️  identify::Event::Received listen addr: {}", addr);

                        let webrtc_address = addr
                            .clone()
                            .with(Protocol::WebRTCDirect)
                            .with(Protocol::P2p(peer_id));

                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, webrtc_address.clone());

                        // TODO (fixme): the below doesn't work because the address is still missing /webrtc/p2p even after https://github.com/libp2p/js-libp2p-webrtc/pull/121
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, addr.clone());

                        tracing::debug!("ℹ️  Added {peer_id} to the routing table.");
                    }
                }
            }

            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                id,
                result,
                ..
            })) => {
                match result {
                    kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                        providers,
                        ..
                    })) => {
                        if let Some(sender) = self.pending_get_providers.remove(&id) {
                            sender.send(providers).expect("Receiver not to be dropped");

                            // Finish the query. We are only interested in the first result.
                            self.swarm
                                .behaviour_mut()
                                .kad
                                .query_mut(&id)
                                .unwrap()
                                .finish();
                        }
                    }
                    kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                        PeerRecord { record, .. },
                    ))) => {
                        if let Some(sender) = self.pending_get_records.remove(&id) {
                            sender
                                .send(record.value.clone())
                                .expect("Receiver not to be dropped");

                            // emit a GotRecord event
                            // so that DHT Records can be retrieved
                            // by users without an async environment

                            // Finish the query. We are only interested in the first result.
                            // TODO: Handle comparing and choosing the best record
                            self.swarm
                                .behaviour_mut()
                                .kad
                                .query_mut(&id)
                                .unwrap()
                                .finish();
                        }
                    }
                    _ => {
                        tracing::warn!("Received unknown Kad QueryResult: {:?}", result);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest {
                request,
                ..
            })) => {
                tracing::debug!("Kademlia Inbound Request: {:?}", request);
                match request {
                    InboundRequest::PutRecord {
                        record: Some(record),
                        source,
                        ..
                    } => {
                        tracing::info!("Received PutRecordRequest from: {:?}", source);

                        // TODO: Filter Providers based on criteria?
                        // for now, add the provider to the DHT as is
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .kad
                            .store_mut()
                            .put(record.clone())
                        {
                            tracing::error!("Failed to add provider to DHT: {e}");
                        }
                    }
                    InboundRequest::AddProvider {
                        record: Some(provider_rec),
                    } => {
                        tracing::info!("Received AddProviderRequest: {:?}", provider_rec);
                        // TODO: Filter Providers based on criteria?
                        // for now, add the provider to the DHT as is
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .kad
                            .store_mut()
                            .add_provider(provider_rec)
                        {
                            tracing::error!("Failed to add provider to DHT: {e}");
                        }
                    }
                    _ => {
                        tracing::warn!("Received unknown InboundRequest: {:?}", request);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(evt)) => {
                tracing::debug!("Kademlia event: {:?}", evt);
            }
            // SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
            //     libp2p::kad::KademliaEvent::OutboundQueryProgressed {
            //         result: libp2p::kad::QueryResult::Bootstrap(res),
            //         ..
            //     },
            // )) => {
            //     debug!("Kademlia BOOTSTRAP Result: {:?}", res);
            // }
            // SwarmEvent::Behaviour(BehaviourEvent::Kademlia(event)) => {
            //     debug!("Kademlia event: {:?}", event)
            // }

            // ignore NewExternalAddrOfPeer
            SwarmEvent::NewExternalAddrOfPeer { .. } => {
                // tracing::debug!("New external address of peer {peer_id}: {address}");
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                tracing::debug!("New external address candidate: {address}");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Bitswap(bitswap)) => match bitswap {
                beetswap::Event::GetQueryResponse { query_id, data } => {
                    tracing::info!("Bitswap: received response for {query_id:?}: {data:?}");
                    match self.pending_queries.get(&query_id) {
                        Some(sendr) => {
                            tracing::info!("received response for {sendr:?}: {data:?}");
                            self.pending_queries
                                .remove(&query_id)
                                .ok_or(Error::StaticStr("Remove failed"))?
                                .send(data)
                                .map_err(|_| {
                                    tracing::error!("Failed to send response for Bitswap result");
                                    Error::StaticStr("Failed to send response")
                                })?;
                        }
                        None => {
                            tracing::info!("received response for unknown cid");
                        }
                    }
                }
                beetswap::Event::GetQueryError { query_id, error } => {
                    tracing::info!("Bitswap: received error for {query_id:?}: {error}");
                    match self.pending_queries.get(&query_id) {
                        Some(cid) => {
                            tracing::info!("received error for {cid:?}: {error}");
                            let sendr = self
                                .pending_queries
                                .remove(&query_id)
                                .ok_or(Error::StaticStr("Remove failed"))?;
                            drop(sendr);
                        }
                        None => {
                            tracing::info!("received error for unknown cid: {error}");
                        }
                    }
                }
            },
            event => {
                tracing::debug!("Other type of event: {:?}", event);
            }
        }
        Ok(())
    }

    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::StartListening { addr, sender } => {
                let _ = match self.swarm.listen_on(addr) {
                    Ok(id) => sender.send(Ok(id)),
                    Err(e) => sender.send(Err(Error::TransportIo(e))),
                };
            }
            NetworkCommand::Dial { addr, sender } => {
                let _ = match self.swarm.dial(addr) {
                    Ok(_) => sender.send(Ok(())),
                    Err(e) => sender.send(Err(Error::Dial(e))),
                };
            }
            NetworkCommand::Publish {
                data: message,
                topic,
            } => {
                tracing::info!("API: Handling Publish command to {topic}");
                let top = libp2p::gossipsub::IdentTopic::new(&topic);
                if let Err(err) = self.swarm.behaviour_mut().gossipsub.publish(top, message) {
                    tracing::error!("Failed to publish message: {err}");

                    // list of all peers
                    let peers = self
                        .swarm
                        .behaviour()
                        .gossipsub
                        .all_peers()
                        .collect::<Vec<_>>();
                    // show explicit peers
                    tracing::info!("All peers: {:?}", peers);

                    // let _ = self
                    //     .event_sender
                    //     .send(Event::Error {
                    //         error: NetworkError::PublishFailed,
                    //     })
                    //     .await;
                }
                tracing::info!("API: Successfully Published to {topic}");
            }
            NetworkCommand::Subscribe { topic } => {
                tracing::info!("API: Handling Subscribe command to {topic}");
                if let Err(err) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&libp2p::gossipsub::IdentTopic::new(&topic))
                {
                    tracing::error!("Failed to subscribe to topic: {err}");
                    let _ = self
                        .event_sender
                        .send(PublicEvent::Error {
                            error: NetworkError::SubscribeFailed,
                        })
                        .await;
                }
                tracing::info!("API: Successfully Subscribed to {topic}");
            }
            NetworkCommand::Unsubscribe { topic } => {
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .unsubscribe(&libp2p::gossipsub::IdentTopic::new(&topic))
                {
                    tracing::error!("Failed to unsubscribe from topic: {topic} {e}");
                    let _ = self
                        .event_sender
                        .send(PublicEvent::Error {
                            error: NetworkError::UnsubscribeFailed,
                        })
                        .await;
                }
            }
            // Add Explicit Peer by PeerId
            NetworkCommand::AddPeer { peer_id } => {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer_id);
                tracing::info!("API: Added Peer {peer_id} to the routing table.");
            }
            // Share the current Multiaddr for the server
            NetworkCommand::ShareMultiaddr => {
                let p2p_addr = self
                    .swarm
                    .external_addresses()
                    .next()
                    .expect("Expected at least one external address.")
                    .clone()
                    .with(Protocol::P2p(*self.swarm.local_peer_id()));

                // emit as Event
                if let Err(e) = self
                    .event_sender
                    .try_send(PublicEvent::ListenAddr {
                        address: p2p_addr.clone(),
                    })
                {
                    tracing::error!("Failed to send share address event: {e}");
                }
            }
            NetworkCommand::Jeeves {
                request,
                peer,
                sender,
            } => {
                tracing::info!("API: Handling RequestResponse command to {peer}");
                let response_id = self
                    .swarm
                    .behaviour_mut()
                    .peer_request
                    .send_request(&peer, PeerRequest::new(request));
                self.pending_requests.insert(response_id, sender);
            }
            // NetworkCommand for Bitwap: TODO here.
            NetworkCommand::BitswapQuery { cid, sender } => {
                tracing::info!("API: Handling BitswapQuery command");
                let Ok(cid) = cid::Cid::try_from(cid) else {
                    tracing::error!("Failed to parse CID");
                    return;
                };
                let query_id = self.swarm.behaviour_mut().bitswap.get(&cid);
                tracing::info!("Bitswap query id: {query_id:?}");
                self.pending_queries.insert(query_id, sender);
                tracing::info!("API: BitswapQuery command sent");
            }
            NetworkCommand::RespondJeeves {
                bytes: file,
                channel,
            } => {
                tracing::info!("API: Handling RespondFile command");
                self.swarm
                    .behaviour_mut()
                    .peer_request
                    .send_response(channel, PeerResponse::new(file))
                    .expect("Connection to peer to be still open.");
            }
            // Put Records on the DHT
            NetworkCommand::PutRecord { key, value } => {
                tracing::info!("API: Handling PutRecord command");
                let record = kad::Record::new(key, value);
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, kad::Quorum::One);
            }
            NetworkCommand::GetRecord { key, sender } => {
                tracing::info!("API: Handling GetRecord command");
                let query_id = self.swarm.behaviour_mut().kad.get_record(key.into());
                self.pending_get_records.insert(query_id, sender);
            }
            NetworkCommand::GetProviders { key, sender } => {
                let query_id = self.swarm.behaviour_mut().kad.get_providers(key.into());
                self.pending_get_providers.insert(query_id, sender);
            }
            NetworkCommand::StartProviding { key } => {
                tracing::info!("API: Handling StartProviding command");
                if let Err(e) = self.swarm.behaviour_mut().kad.start_providing(key.into()) {
                    tracing::error!("Failed to start providing: {e}");
                }
            }
        }
    }
}

