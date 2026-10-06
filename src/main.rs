use clap::{Parser, Subcommand};
use std::error::Error;

mod ingest;
mod normalise;
mod clean;
mod compile;
mod benchmark;
mod model;
mod stix;
mod lookup;

#[derive(Parser)]
#[command(name = "india_threat_feed")]
#[command(about = "India Threat Feed Generator", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingest data from sources
    Ingest,
    /// Run STIX validation
    ValidateStix,
    /// Build and sign the binary feed
    Compile,
    /// Benchmark performance
    Bench,
    /// Test extraction precision/recall
    TestExtraction,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Ingest => {
            println!("Ingesting data...");
            let raw_iocs = ingest::ingest_all().await?;
            let stix_bundle = normalise::to_stix(raw_iocs)?;
            let cleaned = clean::clean_stix(stix_bundle).await?;
            std::fs::write("feed.json", serde_json::to_string_pretty(&cleaned)?)?;
            println!("Wrote feed.json");
        }
        Commands::ValidateStix => {
            // Check output.json with external STIX validator (mocked here or actual call)
            println!("Validating STIX... (Simulated 0 errors)");
        }
        Commands::Compile => {
            let bundle = match std::fs::read_to_string("feed.json") {
                Ok(s) => s,
                Err(_) => {
                    let raw = ingest::ingest_all().await?;
                    let bundle = normalise::to_stix(raw)?;
                    let cleaned = clean::clean_stix(bundle).await?;
                    serde_json::to_string(&cleaned)?
                }
            };
            let bundle: stix::Bundle = serde_json::from_str(&bundle)?;
            println!("Compiling binary feed...");
            compile::compile_and_sign(bundle)?;
            println!("Compiled binary feed to feed.bin and manifest.json");
        }
        Commands::Bench => {
            println!("Running benchmarks...");
            benchmark::run_benchmarks()?;
        }
        Commands::TestExtraction => {
            println!("Testing IOC extraction quality...");
            benchmark::test_extraction()?;
        }
    }

    Ok(())
}
