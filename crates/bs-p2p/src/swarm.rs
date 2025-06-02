//! Create a swarm for your target.
#[cfg(not(target_arch = "wasm32"))]
mod config;
#[cfg(not(target_arch = "wasm32"))]
use config::Config;

use libp2p::{identity::Keypair, relay, swarm::NetworkBehaviour};
// web-time crate uses std::time in native targets
use web_time::Duration;

#[cfg(not(target_os = "android"))]
pub async fn create<B: NetworkBehaviour>(
    behaviour_constructor: impl FnOnce(&Keypair, relay::client::Behaviour) -> B,
    base_path: Option<std::path::PathBuf>,
) -> Result<libp2p::Swarm<B>, String> {
    #[cfg(target_arch = "wasm32")]
    {
        use libp2p::core::upgrade::Version;
        use libp2p::{noise, websocket_websys, yamux, Transport as _};

        Ok(libp2p::SwarmBuilder::with_new_identity()
            .with_wasm_bindgen()
            .with_other_transport(|key| {
                libp2p_webrtc_websys::Transport::new(libp2p_webrtc_websys::Config::new(key))
            })
            .expect("infalliable to never exist")
            .with_other_transport(|local_key| {
                Ok(websocket_websys::Transport::default()
                    .upgrade(Version::V1Lazy)
                    .authenticate(
                        noise::Config::new(local_key)
                            .map_err(|e| format!("failed to initialise noise: {:?}", e))?,
                    )
                    .multiplex(yamux::Config::default()))
            })
            .expect("infalliable to never exist")
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| e.to_string())?
            .with_behaviour(behaviour_constructor)
            .expect("infalliable to never exist")
            // Ping does not KeepAlive, so we set the idle connection timeout to 32_212_254u64,
            // which is the largest value that works with the wasm32 target.
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(32_212_254u64))
            })
            .build())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use libp2p::{noise, yamux};
        use libp2p_webrtc::tokio::Certificate;
        use rand::thread_rng;

        let (keypair, cert) = Config::load(base_path.clone()).unwrap_or_else(|_| {
            tracing::info!("Generating new keypair and certificate");
            let keypair = Keypair::generate_ed25519();
            let cert = Certificate::generate(&mut thread_rng()).unwrap();
            Config::save(&keypair, &cert, base_path).unwrap();
            (keypair, cert)
        });

        tracing::info!("🐝 Loaded keypair and certificate, creating swarm");

        Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic()
            .with_other_transport(|id_keys| {
                Ok(libp2p_webrtc::tokio::Transport::new(id_keys.clone(), cert))
            })
            .map_err(|e| {
                tracing::error!("⭕ Error creating webrtc: {:?}", e);

                e.to_string()
            })?
            .with_dns()
            .map_err(|e| {
                tracing::error!("⭕ Error creating dns: {:?}", e);
                e.to_string()
            })?
            .with_websocket(noise::Config::new, yamux::Config::default)
            .await
            .map_err(|e| {
                tracing::error!("⭕ Error creating websocket: {:?}", e);
                e.to_string()
            })?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| {
                tracing::error!("⭕ Error creating relay client: {:?}", e);
                e.to_string()
            })?
            .with_behaviour(behaviour_constructor)
            .map_err(|e| {
                tracing::error!("⭕ Error creating behaviour: {:?}", e);
                e.to_string()
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(32_212_254u64))
            })
            .build())
    }
}

#[cfg(target_os = "android")]
pub async fn create<B: NetworkBehaviour>(
    behaviour_constructor: impl FnOnce(&Keypair, relay::client::Behaviour) -> B,
    base_path: Option<PathBuf>,
) -> Result<libp2p::Swarm<B>, String> {
    mod config;
    use config::Config;

    use libp2p::{noise, yamux};
    use libp2p_webrtc::tokio::Certificate;
    use rand::thread_rng;

    let (keypair, cert) = Config::load(base_path.clone()).unwrap_or_else(|_| {
        tracing::info!("Generating new keypair and certificate");
        let keypair = Keypair::generate_ed25519();
        let cert = Certificate::generate(&mut thread_rng()).unwrap();
        Config::save(&keypair, &cert, base_path).unwrap();
        (keypair, cert)
    });

    tracing::info!("🐝 Loaded keypair and certificate, creating swarm");

    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_other_transport(|id_keys| {
            Ok(libp2p_webrtc::tokio::Transport::new(id_keys.clone(), cert))
        })
        .map_err(|e| {
            tracing::error!("⭕ Error creating webrtc: {:?}", e);

            e.to_string()
        })?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| {
            tracing::error!("⭕ Error creating relay client: {:?}", e);
            e.to_string()
        })?
        .with_behaviour(behaviour_constructor)
        .map_err(|e| {
            tracing::error!("⭕ Error creating behaviour: {:?}", e);
            e.to_string()
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(32_212_254u64))
        })
        .build())
}
