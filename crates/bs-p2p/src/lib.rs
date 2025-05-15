//! BetterSign SuperPeer crate
#[derive(Default)]
pub struct SuperPeer;

impl SuperPeer {
    /// Runs the [SuperPeer]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize the logger
        let _ = tracing_subscriber::fmt()
            .with_env_filter("bs_p2p=debug")
            .try_init();

        tracing::info!("Starting bestsign_superpeer");

        Ok(())
    }
}
