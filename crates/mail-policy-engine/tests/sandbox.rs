//! The sandbox seam (ADR-0004 sections 4.2 and 7).
//!
//! No WebAssembly runtime is linked into this build, so the host side of the
//! sandbox is a trait with a fail-closed default. These tests pin the
//! contract that a real runtime must satisfy later: a timeout, a trap, an
//! unavailable host or a malformed obligation never results in an allow.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mail_policy_engine::contract::{Effect, PolicyRequest, WireDecision, WireObligation};
use mail_policy_engine::engine::{
    Deadline, EngineError, EngineLimits, HostFailure, ModuleHost, SandboxedPolicyEngine,
    UnavailableModuleHost,
};
use mail_policy_engine::oci::PreparedPolicyModule;

fn module() -> PreparedPolicyModule {
    PreparedPolicyModule::new(
        b"\0asm\x01\0\0\0".to_vec(),
        "sha256:manifest".to_string(),
        "sha256:module".to_string(),
        "corvi-policy-v1".to_string(),
    )
}

fn request() -> PolicyRequest {
    PolicyRequest::new(
        "principal-1",
        "scope-1",
        "message.read",
        "message-42",
        "identity-1",
        "cfg-7",
    )
}

fn limits() -> EngineLimits {
    EngineLimits {
        timeout: Duration::from_millis(50),
        max_obligations: 16,
        max_string_len: 256,
    }
}

/// A host that always answers with the scripted result.
#[derive(Debug)]
struct ScriptedHost {
    result: Result<WireDecision, HostFailure>,
    observed_deadline: Mutex<Option<Duration>>,
}

impl ScriptedHost {
    fn new(result: Result<WireDecision, HostFailure>) -> Self {
        Self {
            result,
            observed_deadline: Mutex::new(None),
        }
    }
}

impl ModuleHost for ScriptedHost {
    fn evaluate(
        &self,
        _module: &PreparedPolicyModule,
        _request: &PolicyRequest,
        deadline: Deadline,
    ) -> Result<WireDecision, HostFailure> {
        *self
            .observed_deadline
            .lock()
            .expect("the mutex is not poisoned") = Some(deadline.timeout);
        self.result.clone()
    }
}

#[test]
fn the_default_host_is_unavailable_and_fails_closed() {
    let engine = SandboxedPolicyEngine::unavailable(limits());

    let error = engine
        .evaluate(&module(), &request())
        .expect_err("there is no runtime in this build");
    assert!(
        matches!(error, EngineError::Host(HostFailure::Unavailable(_))),
        "unexpected error: {error:?}"
    );

    let decision = engine.evaluate_fail_closed(&module(), &request());
    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn the_unavailable_host_reports_an_explicit_status() {
    let host = UnavailableModuleHost::new("no wasm runtime is linked into this build");

    let failure = host
        .evaluate(
            &module(),
            &request(),
            Deadline::new(Duration::from_millis(50)),
        )
        .expect_err("the default host never evaluates anything");

    assert!(matches!(failure, HostFailure::Unavailable(_)));
    assert!(failure.to_string().contains("wasm runtime"));
}

#[test]
fn a_timeout_never_results_in_an_allow() {
    let host = ScriptedHost::new(Err(HostFailure::Timeout));
    let engine = SandboxedPolicyEngine::new(Arc::new(host), limits());

    let decision = engine.evaluate_fail_closed(&module(), &request());

    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn a_trap_never_results_in_an_allow() {
    let host = ScriptedHost::new(Err(HostFailure::Trap("unreachable".to_string())));
    let engine = SandboxedPolicyEngine::new(Arc::new(host), limits());

    let decision = engine.evaluate_fail_closed(&module(), &request());

    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn an_allow_with_malformed_obligations_is_an_error_and_denies() {
    let host = ScriptedHost::new(Ok(WireDecision {
        effect: "allow".to_string(),
        obligations: vec![WireObligation {
            kind: "redact_field".to_string(),
            field_path: None,
        }],
    }));
    let engine = SandboxedPolicyEngine::new(Arc::new(host), limits());

    let error = engine
        .evaluate(&module(), &request())
        .expect_err("malformed obligations are an error");
    assert!(
        matches!(error, EngineError::InvalidDecision(_)),
        "unexpected error: {error:?}"
    );

    let decision = engine.evaluate_fail_closed(&module(), &request());
    assert_eq!(decision.effect, Effect::Deny);
}

#[test]
fn the_host_is_given_the_configured_deadline() {
    let host = Arc::new(ScriptedHost::new(Ok(WireDecision {
        effect: "allow".to_string(),
        obligations: vec![],
    })));
    let engine = SandboxedPolicyEngine::new(host.clone(), limits());

    engine
        .evaluate(&module(), &request())
        .expect("the scripted host allows");

    assert_eq!(
        *host
            .observed_deadline
            .lock()
            .expect("the mutex is not poisoned"),
        Some(Duration::from_millis(50))
    );
}

#[test]
fn too_many_obligations_are_refused() {
    let host = Arc::new(ScriptedHost::new(Ok(WireDecision {
        effect: "allow".to_string(),
        obligations: (0..32)
            .map(|_| WireObligation {
                kind: "sanitize_html".to_string(),
                field_path: None,
            })
            .collect(),
    })));
    let engine = SandboxedPolicyEngine::new(host.clone(), limits());

    let error = engine
        .evaluate(&module(), &request())
        .expect_err("the obligation list is bounded");
    assert!(
        matches!(error, EngineError::LimitExceeded { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn an_oversized_request_field_is_refused_before_the_host_is_called() {
    let host = Arc::new(ScriptedHost::new(Ok(WireDecision {
        effect: "allow".to_string(),
        obligations: vec![],
    })));
    let engine = SandboxedPolicyEngine::new(host.clone(), limits());
    let mut request = request();
    request.principal_id = "p".repeat(1024);

    let error = engine
        .evaluate(&module(), &request)
        .expect_err("request fields are bounded");
    assert!(
        matches!(error, EngineError::LimitExceeded { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        *host
            .observed_deadline
            .lock()
            .expect("the mutex is not poisoned"),
        None
    );
}

#[test]
fn a_valid_allow_is_returned() {
    let host = ScriptedHost::new(Ok(WireDecision {
        effect: "allow".to_string(),
        obligations: vec![WireObligation {
            kind: "sanitize_html".to_string(),
            field_path: None,
        }],
    }));
    let engine = SandboxedPolicyEngine::new(Arc::new(host), limits());

    let decision = engine
        .evaluate(&module(), &request())
        .expect("the scripted host allows");

    assert_eq!(decision.effect, Effect::Allow);
    assert_eq!(decision.obligations.len(), 1);
}
