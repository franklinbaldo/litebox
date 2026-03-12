// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Litebox File Broker — standalone 9P2000.L file server.
//!
//! Serves files from a host directory with policy enforcement and optional
//! ELF syscall rewriting. Communicates with the guest via TCP over the TUN
//! network interface.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::info;

use litebox_broker::policy::{AllowAllPolicy, ReadOnlyPolicy, ReadOnlyWithWritablePaths};

/// Litebox File Broker — policy-enforced file access for sandboxed processes.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Address to listen on (e.g., `10.0.0.1:5640`).
    #[arg(long, default_value = "10.0.0.1:5640")]
    listen_addr: SocketAddr,

    /// Root directory to expose through the broker.
    #[arg(long)]
    root_dir: PathBuf,

    /// Rewrite syscall instructions in ELF files served to the sandbox.
    ///
    /// When enabled, every ELF binary opened through the broker is patched
    /// on the fly to replace syscall instructions with trampoline jumps,
    /// allowing the shim to intercept them without ptrace/seccomp overhead.
    #[arg(long)]
    rewrite_syscalls: bool,

    /// Restrict the broker to read-only access (deny writes, mkdir, unlink, etc.).
    #[arg(long)]
    read_only: bool,

    /// Allow write operations under these directories (can be repeated).
    ///
    /// When specified together with --read-only, write operations are permitted
    /// only for paths that fall under one of these prefixes.  Without --read-only
    /// this flag has no effect.
    #[arg(long = "writable-path")]
    writable_paths: Vec<PathBuf>,
}

fn build_policy(cli: &Cli) -> Arc<dyn litebox_broker::policy::Policy> {
    if cli.read_only {
        if cli.writable_paths.is_empty() {
            Arc::new(ReadOnlyPolicy)
        } else {
            let prefixes: Vec<PathBuf> = cli
                .writable_paths
                .iter()
                .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
                .collect();
            info!(?prefixes, "read-only with writable exceptions");
            Arc::new(ReadOnlyWithWritablePaths::new(prefixes))
        }
    } else {
        Arc::new(AllowAllPolicy)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let policy = build_policy(&cli);

    info!(
        ?root,
        addr = %cli.listen_addr,
        rewrite = cli.rewrite_syscalls,
        read_only = cli.read_only,
        writable_paths = ?cli.writable_paths,
        "starting 9P file broker"
    );

    let listener = std::net::TcpListener::bind(cli.listen_addr)?;
    info!(addr = %cli.listen_addr, "9P server listening");

    // Accept connections one at a time (9P is single-stream per guest)
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => {
                info!(peer = %s.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap()), "9P client connected");
                s
            }
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };

        let mut server = litebox_broker::nine_p::server::Server::new(
            root.clone(),
            Arc::clone(&policy),
            cli.rewrite_syscalls,
        );
        server.serve(&mut stream);
        info!("9P client disconnected");
    }

    Ok(())
}
