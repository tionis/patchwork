use clap::Parser;
use patchwork::cli::{Cli, run};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = run(Cli::parse().command).await;
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
