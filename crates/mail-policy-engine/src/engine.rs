//! The sandbox seam for policy evaluation.
//!
//! ADR-0004 section 4.2 requires that a policy module runs in a sandbox with
//! fuel, memory and deadline limits, and that a trap, an exceeded limit, an
//! unexpected output or a timeout fails closed.
//!
//! No WebAssembly runtime is linked into this build, so the host side of the
//! sandbox is a trait. [`UnavailableModuleHost`] is the default: it reports
//! that no runtime is available and never returns a decision. A later task
//! that adds a runtime implements [`ModuleHost`] and plugs it in here; the
//! evaluation contract around it - the deadline, the bounded obligations, the
//! validation of the returned decision and the fail-closed behaviour - does
//! not change.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::contract::{DecisionError, Effect, PolicyDecision, PolicyRequest, WireDecision};
use crate::oci::artifact::PreparedPolicyModule;

/// The deadline of one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// How long the evaluation may take.
    pub timeout: Duration,
}

impl Deadline {
    /// A deadline with the given timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

/// Why a host could not produce a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFailure {
    /// The host is not available in this build or deployment.
    Unavailable(String),
    /// The host does not support this module.
    Unsupported(String),
    /// The evaluation exceeded its deadline.
    Timeout,
    /// The module trapped.
    Trap(String),
    /// The host returned something that is not a decision.
    InvalidOutput(String),
}

impl fmt::Display for HostFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFailure::Unavailable(reason) => {
                write!(formatter, "the policy host is unavailable: {reason}")
            }
            HostFailure::Unsupported(reason) => {
                write!(
                    formatter,
                    "the policy host does not support this module: {reason}"
                )
            }
            HostFailure::Timeout => write!(formatter, "the policy evaluation timed out"),
            HostFailure::Trap(reason) => write!(formatter, "the policy module trapped: {reason}"),
            HostFailure::InvalidOutput(reason) => {
                write!(
                    formatter,
                    "the policy host returned an unusable result: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for HostFailure {}

/// A host that evaluates a policy module.
///
/// A host is the only place where a policy module runs. It is responsible for
/// the sandbox: no filesystem, no network, no clocks, no randomness and no
/// environment unless the local allowlist grants them.
pub trait ModuleHost: Send + Sync + fmt::Debug {
    /// Evaluate the module for one request.
    ///
    /// The host must respect the deadline and must return the raw decision as
    /// it received it: validation happens in [`SandboxedPolicyEngine`], so a
    /// malformed decision is an error rather than a partially honoured result.
    fn evaluate(
        &self,
        module: &PreparedPolicyModule,
        request: &PolicyRequest,
        deadline: Deadline,
    ) -> Result<WireDecision, HostFailure>;
}

/// The default host: no runtime is linked into this build.
///
/// It never returns a decision, so an installation without a sandboxed runtime
/// fails closed for the operations that depend on one.
#[derive(Debug, Clone)]
pub struct UnavailableModuleHost {
    reason: String,
}

impl UnavailableModuleHost {
    /// A host that reports the given reason.
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

impl Default for UnavailableModuleHost {
    fn default() -> Self {
        Self::new("no wasm runtime is linked into this build")
    }
}

impl ModuleHost for UnavailableModuleHost {
    fn evaluate(
        &self,
        _module: &PreparedPolicyModule,
        _request: &PolicyRequest,
        _deadline: Deadline,
    ) -> Result<WireDecision, HostFailure> {
        Err(HostFailure::Unavailable(self.reason.clone()))
    }
}

/// The resource limits of the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineLimits {
    /// The wall-clock deadline of one evaluation.
    pub timeout: Duration,
    /// The largest number of obligations a decision may carry.
    pub max_obligations: usize,
    /// The largest length of a request field.
    pub max_string_len: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(50),
            max_obligations: 16,
            max_string_len: 256,
        }
    }
}

/// Why an evaluation produced no decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// The host failed.
    Host(HostFailure),
    /// The decision the host returned is not usable.
    InvalidDecision(DecisionError),
    /// A bound was exceeded.
    LimitExceeded {
        /// What was bounded.
        kind: &'static str,
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Host(failure) => write!(formatter, "{failure}"),
            EngineError::InvalidDecision(error) => write!(formatter, "{error}"),
            EngineError::LimitExceeded { kind, limit } => {
                write!(formatter, "the {kind} limit of {limit} was exceeded")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// The sandboxed policy engine.
#[derive(Debug)]
pub struct SandboxedPolicyEngine {
    host: Arc<dyn ModuleHost>,
    limits: EngineLimits,
}

impl SandboxedPolicyEngine {
    /// An engine that evaluates through the given host.
    pub fn new(host: Arc<dyn ModuleHost>, limits: EngineLimits) -> Self {
        Self { host, limits }
    }

    /// An engine whose host is unavailable, which is the state of an
    /// installation without a sandboxed runtime.
    pub fn unavailable(limits: EngineLimits) -> Self {
        Self::new(Arc::new(UnavailableModuleHost::default()), limits)
    }

    /// The limits of the engine.
    pub fn limits(&self) -> &EngineLimits {
        &self.limits
    }

    /// Evaluate one request.
    ///
    /// Every failure is an error. The caller decides what an error means for
    /// its operation; [`SandboxedPolicyEngine::evaluate_fail_closed`] is the
    /// convenience for the common case.
    pub fn evaluate(
        &self,
        module: &PreparedPolicyModule,
        request: &PolicyRequest,
    ) -> Result<PolicyDecision, EngineError> {
        self.check_request(request)?;

        let wire = self
            .host
            .evaluate(module, request, Deadline::new(self.limits.timeout))
            .map_err(EngineError::Host)?;

        let decision = wire.validate().map_err(EngineError::InvalidDecision)?;

        if decision.obligations.len() > self.limits.max_obligations {
            return Err(EngineError::LimitExceeded {
                kind: "obligation count",
                limit: self.limits.max_obligations,
            });
        }

        Ok(decision)
    }

    /// Evaluate one request and fail closed.
    ///
    /// A timeout, a trap, an unavailable host or a malformed decision never
    /// results in an allow.
    pub fn evaluate_fail_closed(
        &self,
        module: &PreparedPolicyModule,
        request: &PolicyRequest,
    ) -> PolicyDecision {
        match self.evaluate(module, request) {
            Ok(decision) => decision,
            Err(_) => PolicyDecision {
                effect: Effect::Deny,
                obligations: Vec::new(),
            },
        }
    }

    /// Check the request against the limits before the host is called.
    fn check_request(&self, request: &PolicyRequest) -> Result<(), EngineError> {
        let fields = [
            request.principal_id.as_str(),
            request.credential_scope_id.as_str(),
            request.action.as_str(),
            request.resource_id.as_str(),
            request.identity_id.as_str(),
            request.configuration_revision.as_str(),
        ];

        for field in fields {
            if field.len() > self.limits.max_string_len {
                return Err(EngineError::LimitExceeded {
                    kind: "request field length",
                    limit: self.limits.max_string_len,
                });
            }
        }

        Ok(())
    }
}
