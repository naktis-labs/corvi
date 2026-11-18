//! The standalone Corvi mail gateway.
//!
//! One process serves the REST and MCP surfaces over one service pipeline.
//! It reads a credential snapshot, a disclosure policy document and an
//! upstream backend, and it serves on the address the snapshot declares.
//!
//! ```text
//! corvi-gateway --config snapshot.yaml --policies policies.yaml --upstream fixtures.json
//! corvi-gateway --config snapshot.yaml --policies policies.yaml --upstream fixtures.json --check
//! ```
//!
//! `--check` validates the configuration and exits without listening.
//!
//! The snapshot requires a loopback listener and an explicit
//! `allow_loopback_plaintext`, so this process serves plaintext on the
//! loopback interface only. Terminating TLS in front of it, or exposing it
//! through a trusted TLS terminator, is the deployment's job; see ADR-0006,
//! which is not implemented.

use std::path::PathBuf;
use std::sync::Arc;

use mail_api::fixture::FixtureUpstream;
use mail_api::mcp::McpServer;
use mail_api::policy::PolicyStore;
use mail_api::rest::{AppState, router};
use mail_api::service::GatewayBuilder;
use mail_config::{Snapshot, SnapshotStore};

/// The arguments the process was started with.
#[derive(Debug)]
struct Options {
    config: PathBuf,
    policies: PathBuf,
    upstream: PathBuf,
    check_only: bool,
}

/// Parse the command line.
fn parse_options() -> Result<Options, String> {
    let mut config = None;
    let mut policies = None;
    let mut upstream = None;
    let mut check_only = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    arguments.next().ok_or("--config needs a path")?,
                ));
            }
            "--policies" => {
                policies = Some(PathBuf::from(
                    arguments.next().ok_or("--policies needs a path")?,
                ));
            }
            "--upstream" => {
                upstream = Some(PathBuf::from(
                    arguments.next().ok_or("--upstream needs a path")?,
                ));
            }
            "--check" => check_only = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(Options {
        config: config.ok_or("--config is required")?,
        policies: policies.ok_or("--policies is required")?,
        upstream: upstream.ok_or("--upstream is required")?,
        check_only,
    })
}

fn main() -> std::process::ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("corvi-gateway: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    match run(options) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("corvi-gateway: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Load the configuration and either check it or serve it.
fn run(options: Options) -> Result<(), String> {
    let snapshot = Snapshot::from_file(&options.config)
        .map_err(|error| format!("the snapshot could not be read: {error}"))?;
    let config = Arc::new(
        SnapshotStore::new(snapshot)
            .map_err(|error| format!("the snapshot is invalid: {error}"))?,
    );
    let policy_text = std::fs::read_to_string(&options.policies)
        .map_err(|error| format!("the policy document could not be read: {error}"))?;
    let policies = Arc::new(
        PolicyStore::from_yaml(&policy_text)
            .map_err(|error| format!("the policy document is invalid: {error}"))?,
    );
    let upstream_text = std::fs::read_to_string(&options.upstream)
        .map_err(|error| format!("the upstream could not be read: {error}"))?;
    let upstream = Arc::new(
        FixtureUpstream::from_json(&upstream_text)
            .map_err(|error| format!("the upstream is invalid: {error}"))?,
    );

    if options.check_only {
        println!(
            "configuration is valid: listen {}, {} identities, {} policies",
            config.active().listen(),
            config.active().identities().len(),
            policies.policy_ids().count(),
        );
        return Ok(());
    }

    let listen = config.active().listen();
    let smtp_listen = config.active().smtp_listen();
    let gateway = GatewayBuilder::new(config.clone(), policies, upstream).build();
    let state = AppState {
        gateway: gateway.clone(),
        mcp: McpServer::new(gateway.clone()),
    };
    let app = router(state);

    if let Some(smtp_listen) = smtp_listen {
        let listener = std::net::TcpListener::bind(smtp_listen)
            .map_err(|error| format!("the SMTP listener could not be bound: {error}"))?;
        println!("corvi-gateway accepts SMTP AUTH submissions on {smtp_listen}");
        let smtp_gateway = Arc::new(gateway.clone());
        std::thread::spawn(move || {
            if let Err(error) = mail_api::smtp::serve(smtp_gateway, listener) {
                eprintln!("corvi-gateway: the SMTP listener stopped: {error}");
            }
        });
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the runtime could not be started: {error}"))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|error| format!("the listener could not be bound: {error}"))?;
        println!("corvi-gateway is listening on {listen}");
        axum::serve(listener, app)
            .await
            .map_err(|error| format!("the server stopped: {error}"))
    })
}
