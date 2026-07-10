//! Run a MoLE Anchor server.

use std::sync::Arc;

use clap::Parser;
use mole_anchor::{router, AnchorState, DEFAULT_GRANTS_PER_EPOCH};

#[derive(Parser)]
#[command(about = "MoLE Anchor: grants IHAT Endorsements")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 8081)]
    port: u16,
    /// The endorsement context (epoch) to grant under.
    #[arg(long, default_value = "epoch-demo-1")]
    endorsement_context: String,
    /// Endorsements granted per user per epoch.
    #[arg(long, default_value_t = DEFAULT_GRANTS_PER_EPOCH)]
    grants_per_epoch: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let state = Arc::new(AnchorState::new(
        args.endorsement_context.clone().into_bytes(),
        args.grants_per_epoch,
    ));
    tracing::info!(
        port = args.port,
        endorsement_context = %args.endorsement_context,
        "anchor listening"
    );

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", args.port)).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
