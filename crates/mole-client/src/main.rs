//! The MoLE Client CLI.

use clap::{Parser, Subcommand};
use mole_client::MoleClient;

#[derive(Parser)]
#[command(about = "MoLE Client: fetch resources protected by a Moderator")]
struct Args {
    /// Origin of the Anchor to obtain Endorsements from.
    #[arg(long)]
    anchor: String,
    /// The demo username establishing trust with the Anchor.
    #[arg(long, default_value = "alice")]
    user: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a protected resource, running the MoLE flows as needed.
    Fetch {
        /// The resource URL.
        url: String,
        /// How many times to fetch (later fetches reuse the Credential).
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut client = MoleClient::new(args.anchor.trim_end_matches('/'), args.user);

    match args.command {
        Command::Fetch { url, count } => {
            for i in 1..=count {
                let outcome = client.fetch(&url).await?;
                println!(
                    "fetch {i}/{count}: {}{}",
                    outcome.body.trim_end(),
                    if outcome.redeemed {
                        "  (ran redeem & issue)"
                    } else {
                        "  (presented stored credential)"
                    }
                );
            }
        }
    }
    Ok(())
}
