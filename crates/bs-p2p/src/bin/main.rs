#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("bs_p2p=debug")
        .try_init();

    tracing::info!("Starting bestsign_superpeer BINARY");

    let mut superpeer = bs_p2p::SuperPeer::default();

    superpeer.run().await?;

    Ok(())
}
