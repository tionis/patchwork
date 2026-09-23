use clap::Parser;
use patchwork::cli::{Cli, Command, check_health};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Command::Health { url } => check_health(&url).await,
    };
    match result {
        Ok(()) => {
            println!("healthy");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
