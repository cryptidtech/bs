//! This module defines the behaviour of the network.
pub(crate) mod req_res;

use std::time::Duration;

use blockstore::Blockstore;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{dcutr, relay, StreamProtocol};
use libp2p::{gossipsub, identify, identity::Keypair, kad, ping, swarm::NetworkBehaviour};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use req_res::{PeerRequest, PeerResponse};

/// [kad] [StreamProtocol] name
const PROTOCOL_NAME: &str = "/bettersign/0.1.0";

/// Extension protocol name
///
/// Work in progress.
const EXTENSION_PROTOCOL: &str = "/bettersign/extensions/0.1.0";

const MAX_MULTIHASH_LENGTH: usize = 64;

/// The [NetworkBehaviour] also creates a [BehaviourEvent] for us, which we can use to
/// handle events from the behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour<B: Blockstore + 'static> {
    /// Ping remote peers
    pub(crate) ping: ping::Behaviour,
    /// Publish subscribe to topics
    pub(crate) gossipsub: gossipsub::Behaviour,
    /// Identify ourselves to other peers
    pub(crate) identify: identify::Behaviour,
    /// Kademlia DHT for Peer management
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    /// Use RequestResponse to send data to a peer. Extensions can be used
    /// to encode/decode the bytes, giving users a lot of flexibility that they control.
    pub(crate) peer_request: request_response::cbor::Behaviour<PeerRequest, PeerResponse>,
    /// Relay client
    pub(crate) relay_client: relay::client::Behaviour,
    /// Dcutr
    dcutr: dcutr::Behaviour,
    /// Bitswap
    pub(crate) bitswap: beetswap::Behaviour<MAX_MULTIHASH_LENGTH, B>,
}

/// BehaviousBuilder lets us set the bitswap [Blockstore] first,
/// then build with key and relay behaviour later.
pub struct BehaviourBuilder<B: Blockstore + 'static> {
    blockstore: B,
}

impl<B: Blockstore + 'static> BehaviourBuilder<B> {
    pub fn new(blockstore: B) -> Self {
        Self { blockstore }
    }

    pub fn build(self, key: &Keypair, relay_behaviour: relay::client::Behaviour) -> Behaviour<B> {
        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        // Set a custom gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(15)) // This is set to aid debugging by not cluttering the log space
            .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .support_floodsub()
            .flood_publish(true)
            .build()
            .unwrap_or_default();

        // build a gossipsub network behaviour
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        )
        .expect("Config should be valid");

        let mut kad_config = kad::Config::new(StreamProtocol::new(PROTOCOL_NAME));
        // allows us to validate records before inserting them into the store
        // when enabled, we will see the kad event InboundRequest(PutRecord) where we would then
        // validate the record and act on the record
        //kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);

        let kad = kad::Behaviour::with_config(
            key.public().to_peer_id(),
            kad::store::MemoryStore::new(key.public().to_peer_id()),
            kad_config,
        );

        let bitswap = beetswap::Behaviour::new(self.blockstore.into());

        Behaviour {
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(25))),
            // Need to include identify until https://github.com/status-im/nim-libp2p/issues/924 is resolved.
            identify: identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_owned(),
                key.public(),
            )),
            gossipsub,
            kad,
            peer_request: request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::new(EXTENSION_PROTOCOL),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
            ),
            relay_client: relay_behaviour,
            dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
            bitswap,
        }
    }
}

// test and not wasm target
#[cfg(test)]
mod tests {
    // NOTE: The StandardMultihasher is incompatible with the cryptid multihash type

    // use beetswap::multihasher::{Multihasher as _, StandardMultihasher};
    // use sha3::{Digest, Sha3_512};
    //
    // /// Sha3-512 length is 64 bytes
    // const SHA3_512_LEN: usize = 64;
    //
    // /// Multicodec for Sha3-512, see [multiformats/multicodec](https://github.com/multiformats/multicodec/blob/df81972d764f30da4ad32e1e5b778d8b619de477/table.csv#L15-L16) for details
    // /// The code for sha3-512 is hex 0x14, decimal 20
    // pub const SHA3_512_HASH_CODE: u64 = 0x14;
    //
    // #[tokio::test]
    // async fn test_standard_sha3_512_multihasher() {
    //     use multihash_codetable::Code;
    //
    //     let input = b"hello world";
    //
    //     let digest = Sha3_512::digest(input);
    //
    //     let len = digest.len();
    //     assert_eq!(len, SHA3_512_LEN);
    //
    //     let result: multihash::Multihash = StandardMultihasher
    //         .hash(Code::Sha3_512.into(), input)
    //         .await
    //         .unwrap();
    //
    //     assert_eq!(result.code(), SHA3_512_HASH_CODE);
    //     assert_eq!(result.digest(), digest.as_slice());
    // }
}
