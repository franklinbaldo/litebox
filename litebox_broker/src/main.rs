// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox File Broker — standalone broker binary.
//!
//! Starts a gRPC server that provides policy-enforced file system access to
//! sandboxed processes.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tonic::transport::Server;
use tracing::info;

use litebox_broker::policy::AllowAllPolicy;
use litebox_broker::proto::file_broker_server::FileBrokerServer;
use litebox_broker::server::FileBrokerService;

/// Litebox File Broker — policy-enforced file access for sandboxed processes.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Address to listen on (e.g., 127.0.0.1:50051).
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen_addr: SocketAddr,

    /// Root directory to expose through the broker.
    #[arg(long)]
    root_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let root = cli
        .root_dir
        .canonicalize()
        .expect("root directory must exist");

    info!(?root, addr = %cli.listen_addr, "starting file broker");

    let policy = Arc::new(AllowAllPolicy);
    let service = FileBrokerService::new(root, policy);

    Server::builder()
        .add_service(FileBrokerServer::new(service))
        .serve(cli.listen_addr)
        .await?;

    Ok(())
}
