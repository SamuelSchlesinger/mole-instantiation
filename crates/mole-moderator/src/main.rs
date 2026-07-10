//! Run a MoLE Moderator server.

use std::sync::Arc;

use clap::Parser;
use mole_core::config::{AnchorDirectory, ANCHOR_DIRECTORY_PATH};
use mole_core::http::b64_decode;
use mole_moderator::{router, ModeratorConfig, ModeratorState};

#[derive(Parser)]
#[command(about = "MoLE Moderator: challenges, Redeem & Issue, Presentation and Update")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Anchor origins to trust (their directories are fetched at startup).
    #[arg(long, required = true)]
    anchor: Vec<String>,
    /// Policy identifier.
    #[arg(long, default_value = "policy-demo-1")]
    policy_context: String,
    /// Credits granted at Redeem & Issue.
    #[arg(long, default_value_t = 10)]
    initial_credits: u64,
    /// Charge per presentation.
    #[arg(long, default_value_t = 1)]
    charge: u64,
    /// Refund returned with each update (0..=charge).
    #[arg(long, default_value_t = 0)]
    refund: u64,
}

fn main() -> anyhow::Result<()> {
    // ACT proof generation and verification need more stack than tokio's
    // default 2 MiB worker threads provide.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 * 1024 * 1024)
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Fetch each trusted Anchor's directory; the accepted set is their keys,
    // in the (normative) order given on the command line.
    let mut accepted_anchor_keys = Vec::new();
    let mut endorsement_context: Option<Vec<u8>> = None;
    for origin in &args.anchor {
        let url = format!("{}{}", origin.trim_end_matches('/'), ANCHOR_DIRECTORY_PATH);
        let directory: AnchorDirectory = reqwest::get(&url).await?.json().await?;
        let config = directory
            .endorsement_configs
            .iter()
            .find(|c| c.endorsement_type == mole_core::endorsement_type::IHAT)
            .ok_or_else(|| anyhow::anyhow!("{origin} offers no IHAT config"))?;
        let key: [u8; 33] = b64_decode(&config.public_key)
            .map_err(|e| anyhow::anyhow!("{origin}: bad key encoding: {e}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("{origin}: key is not 33 bytes"))?;
        accepted_anchor_keys.push(key);

        let context = b64_decode(&config.endorsement_context)
            .map_err(|e| anyhow::anyhow!("{origin}: bad context encoding: {e}"))?;
        match &endorsement_context {
            None => endorsement_context = Some(context),
            Some(existing) if *existing == context => {}
            Some(_) => anyhow::bail!("anchors disagree on the endorsement context (epoch)"),
        }
    }

    let state = Arc::new(ModeratorState::new(ModeratorConfig {
        policy_context: args.policy_context.into_bytes(),
        accepted_anchor_keys,
        endorsement_context: endorsement_context.expect("at least one anchor"),
        initial_credits: args.initial_credits,
        charge: args.charge,
        refund: args.refund,
        act_domain_separator: b"MoLE-instantiation:act:v1".to_vec(),
    })?);

    tracing::info!(port = args.port, anchors = args.anchor.len(), "moderator listening");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", args.port)).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
