//! The `corvi-operator` binary: it watches `CorviGateway` resources in one
//! namespace and reconciles each to its hardened workload.
//!
//! The configuration comes from the environment and fails closed: without a
//! digest-pinned gateway image the operator refuses to start, because
//! ADR-0011 forbids mutable image references and the renderer refuses them
//! anyway.

use corvi_operator::kube::OperatorClient;
use corvi_operator::reconcile_gateway;
use mail_operator::workload::{OperatorProfile, PolicyExpectation, PolicyKind, PolicySource};

/// The environment the operator runs with.
struct Config {
    namespace: String,
    profile: OperatorProfile,
    resync_seconds: u64,
}

/// The default resync period in seconds (five minutes).
const DEFAULT_RESYNC_SECONDS: u64 = 300;

/// The resync period is clamped into this range: a period near zero would
/// hammer the API server, an unbounded one would leave objects unreconciled.
const MIN_RESYNC_SECONDS: u64 = 10;
const MAX_RESYNC_SECONDS: u64 = 3600;

/// Why the operator refused to start.
struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn config_from_env() -> Result<Config, ConfigError> {
    let variable = |name: &str| -> Result<String, ConfigError> {
        std::env::var(name).map_err(|_| ConfigError(format!("{name} is required")))
    };
    let image = variable("CORVI_GATEWAY_IMAGE")?;
    if !digest_pinned(&image) {
        return Err(ConfigError(
            "CORVI_GATEWAY_IMAGE must be digest-pinned (ADR-0011 section 5)".into(),
        ));
    }
    let namespace = std::env::var("CORVI_NAMESPACE").unwrap_or_else(|_| "corvi-system".to_owned());
    let operator_sa =
        std::env::var("CORVI_OPERATOR_SA").unwrap_or_else(|_| "corvi-operator".to_owned());
    let gateway_sa =
        std::env::var("CORVI_GATEWAY_SA").unwrap_or_else(|_| "corvi-gateway".to_owned());
    if operator_sa == gateway_sa {
        return Err(ConfigError(
            "the operator and the gateway must use different service accounts (ADR-0011 section 3)"
                .into(),
        ));
    }
    let profile = OperatorProfile {
        gateway_image: image,
        operator_service_account: operator_sa,
        gateway_service_account: gateway_sa,
        http_port: port_env("CORVI_HTTP_PORT", 8080)?,
        smtp_submission_port: port_env("CORVI_SMTP_SUBMISSION_PORT", 2525)?,
        admission_policy: PolicyExpectation {
            name: std::env::var("CORVI_ADMISSION_POLICY")
                .unwrap_or_else(|_| "corvi-restricted-workload".to_owned()),
            kind: PolicyKind::Admission,
            source: PolicySource::IndependentlyInstalled,
        },
        network_policy: PolicyExpectation {
            name: std::env::var("CORVI_NETWORK_POLICY")
                .unwrap_or_else(|_| "corvi-gateway-default-deny".to_owned()),
            kind: PolicyKind::Network,
            source: PolicySource::IndependentlyInstalled,
        },
    };
    let resync_seconds = std::env::var("CORVI_RESYNC_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_RESYNC_SECONDS)
        .clamp(MIN_RESYNC_SECONDS, MAX_RESYNC_SECONDS);

    Ok(Config {
        namespace,
        profile,
        resync_seconds,
    })
}

/// Whether an image reference is pinned to an immutable sha256 digest.
fn digest_pinned(image: &str) -> bool {
    let Some((_, digest)) = image.split_once('@') else {
        return false;
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn port_env(name: &str, default: u16) -> Result<u16, ConfigError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| ConfigError(format!("{name} must be an unprivileged port number"))),
        Err(_) => Ok(default),
    }
}

fn main() {
    let config = match config_from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("corvi-operator: refusing to start: {error}");
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    if let Err(error) = runtime.block_on(run(config)) {
        eprintln!("corvi-operator: {error}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), String> {
    let operator = OperatorClient::connect(&config.namespace)
        .await
        .map_err(|error| error.to_string())?;
    println!(
        "corvi-operator: watching CorviGateway resources in namespace {}",
        operator.namespace()
    );
    loop {
        reconcile_all(&operator, &config).await;
        tokio::time::sleep(std::time::Duration::from_secs(config.resync_seconds)).await;
    }
}

/// One full pass over the namespace. A watch-driven loop is a later slice;
/// this bounded resync is correct, simple, and cannot miss an event.
async fn reconcile_all(operator: &OperatorClient, config: &Config) {
    let names = match corvi_operator::kube::list_gateway_names(operator.gateways()).await {
        Ok(names) => names,
        Err(error) => {
            eprintln!("corvi-operator: resync failed: {error}");
            return;
        }
    };
    for name in names {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| i64::try_from(since.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        match reconcile_gateway(operator, operator.namespace(), &name, &config.profile, now).await {
            Ok(outcome) => println!("corvi-operator: {name}: {outcome:?}"),
            Err(error) => eprintln!("corvi-operator: {name}: {error}"),
        }
    }
}
