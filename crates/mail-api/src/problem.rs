//! Typed error surfaces for both protocol adapters.
//!
//! ADR-0005 requires every refusal to be a stable, non-sensitive code, and
//! `docs/spec/mcp.md` section 8 requires that a hidden message and a message
//! that does not exist are indistinguishable. The constructors here are the
//! only way a failure becomes a response, so the mapping from a refusal to a
//! status code is written down once.

use serde::{Deserialize, Serialize};

/// A stable error code.
///
/// The names are the vocabulary `docs/spec/mcp.md` section 8 proposes, plus
/// the two transport-level codes REST needs and MCP inherits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// The caller presented no usable credential.
    Unauthorized,
    /// The resource is absent, hidden, or outside the authorized identity.
    NotFound,
    /// The caller may act on the identity but not with this action.
    Forbidden,
    /// The request was malformed or out of range.
    InvalidInput,
    /// The cursor expired or could not be verified.
    CursorInvalid,
    /// The caller, filter policy or configuration changed under the cursor.
    CursorStale,
    /// Eligibility could not be decided safely.
    FilterUnavailable,
    /// The upstream transport could not complete the operation.
    UpstreamUnavailable,
    /// The caller exceeded its operation budget.
    RateLimited,
    /// The attachment is larger than the protocol allows.
    AttachmentTooLarge,
    /// The idempotency key was reused for a different message.
    IdempotencyConflict,
    /// The submission outcome is ambiguous.
    SendOutcomeUnknown,
    /// The host cannot ask the user for confirmation.
    ConfirmationRequired,
    /// An unexpected internal failure.
    Internal,
}

impl ErrorCode {
    /// The wire name of the code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Forbidden => "FORBIDDEN",
            ErrorCode::InvalidInput => "INVALID_INPUT",
            ErrorCode::CursorInvalid => "CURSOR_INVALID",
            ErrorCode::CursorStale => "CURSOR_STALE",
            ErrorCode::FilterUnavailable => "FILTER_UNAVAILABLE",
            ErrorCode::UpstreamUnavailable => "UPSTREAM_UNAVAILABLE",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::AttachmentTooLarge => "ATTACHMENT_TOO_LARGE",
            ErrorCode::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            ErrorCode::SendOutcomeUnknown => "SEND_OUTCOME_UNKNOWN",
            ErrorCode::ConfirmationRequired => "CONFIRMATION_REQUIRED",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// The HTTP status the code maps to.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::Unauthorized => 401,
            ErrorCode::NotFound => 404,
            ErrorCode::Forbidden => 403,
            ErrorCode::InvalidInput => 400,
            ErrorCode::CursorInvalid => 400,
            ErrorCode::CursorStale => 409,
            ErrorCode::FilterUnavailable => 503,
            ErrorCode::UpstreamUnavailable => 503,
            ErrorCode::RateLimited => 429,
            ErrorCode::AttachmentTooLarge => 413,
            ErrorCode::IdempotencyConflict => 409,
            ErrorCode::SendOutcomeUnknown => 202,
            ErrorCode::ConfirmationRequired => 428,
            ErrorCode::Internal => 500,
        }
    }

    /// The URI that names this kind of problem.
    pub fn problem_type(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "https://corvi.naktis.eu/problems/unauthorized",
            ErrorCode::NotFound => "https://corvi.naktis.eu/problems/not-found",
            ErrorCode::Forbidden => "https://corvi.naktis.eu/problems/forbidden",
            ErrorCode::InvalidInput => "https://corvi.naktis.eu/problems/invalid-input",
            ErrorCode::CursorInvalid => "https://corvi.naktis.eu/problems/cursor-invalid",
            ErrorCode::CursorStale => "https://corvi.naktis.eu/problems/cursor-stale",
            ErrorCode::FilterUnavailable => "https://corvi.naktis.eu/problems/filter-unavailable",
            ErrorCode::UpstreamUnavailable => {
                "https://corvi.naktis.eu/problems/upstream-unavailable"
            }
            ErrorCode::RateLimited => "https://corvi.naktis.eu/problems/rate-limited",
            ErrorCode::AttachmentTooLarge => {
                "https://corvi.naktis.eu/problems/attachment-too-large"
            }
            ErrorCode::IdempotencyConflict => {
                "https://corvi.naktis.eu/problems/idempotency-conflict"
            }
            ErrorCode::SendOutcomeUnknown => {
                "https://corvi.naktis.eu/problems/send-outcome-unknown"
            }
            ErrorCode::ConfirmationRequired => {
                "https://corvi.naktis.eu/problems/confirmation-required"
            }
            ErrorCode::Internal => "https://corvi.naktis.eu/problems/internal",
        }
    }

    /// The short human-readable title of the problem.
    pub fn title(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "Authentication required",
            ErrorCode::NotFound => "Not found",
            ErrorCode::Forbidden => "Not permitted",
            ErrorCode::InvalidInput => "Invalid request",
            ErrorCode::CursorInvalid => "Invalid cursor",
            ErrorCode::CursorStale => "Stale cursor",
            ErrorCode::FilterUnavailable => "Filter unavailable",
            ErrorCode::UpstreamUnavailable => "Upstream unavailable",
            ErrorCode::RateLimited => "Rate limited",
            ErrorCode::AttachmentTooLarge => "Attachment too large",
            ErrorCode::IdempotencyConflict => "Idempotency conflict",
            ErrorCode::SendOutcomeUnknown => "Submission outcome unknown",
            ErrorCode::ConfirmationRequired => "Confirmation required",
            ErrorCode::Internal => "Internal error",
        }
    }
}

/// An RFC 9457 problem document.
///
/// The document never names a hidden message, a matched rule, a subject, a
/// sender or an upstream identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The problem type URI.
    #[serde(rename = "type")]
    pub problem_type: &'static str,
    /// The short summary of the problem.
    pub title: &'static str,
    /// The HTTP status.
    pub status: u16,
    /// The stable Corvi error code.
    pub code: &'static str,
    /// A sanitized detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The opaque diagnostic identifier of the request.
    #[serde(rename = "traceId")]
    pub trace_id: String,
}

impl Problem {
    /// Build a problem for a code with an optional detail.
    pub fn new(code: ErrorCode, detail: Option<String>) -> Self {
        Self {
            problem_type: code.problem_type(),
            title: code.title(),
            status: code.status(),
            code: code.as_str(),
            detail,
            trace_id: crate::time::random_id(),
        }
    }

    /// The caller presented no usable credential.
    pub fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized, None)
    }

    /// The resource is absent, hidden or outside the authorized identity.
    ///
    /// This is the answer for a hidden message as well as for one that does
    /// not exist, so the two are indistinguishable to the caller.
    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, None)
    }

    /// The caller may act on the identity but not with this action.
    pub fn forbidden() -> Self {
        Self::new(ErrorCode::Forbidden, None)
    }

    /// The request was malformed.
    pub fn invalid_input(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, Some(detail.into()))
    }

    /// The cursor could not be verified.
    pub fn cursor_invalid() -> Self {
        Self::new(ErrorCode::CursorInvalid, None)
    }

    /// The cursor was issued for a different caller, identity or policy.
    pub fn cursor_stale() -> Self {
        Self::new(ErrorCode::CursorStale, None)
    }

    /// The upstream transport could not complete the operation.
    pub fn upstream_unavailable() -> Self {
        Self::new(ErrorCode::UpstreamUnavailable, None)
    }

    /// The attachment is larger than the protocol allows.
    pub fn attachment_too_large() -> Self {
        Self::new(ErrorCode::AttachmentTooLarge, None)
    }

    /// The idempotency key was reused for a different message.
    pub fn idempotency_conflict() -> Self {
        Self::new(ErrorCode::IdempotencyConflict, None)
    }

    /// The host cannot ask the user to confirm the send.
    pub fn confirmation_required() -> Self {
        Self::new(ErrorCode::ConfirmationRequired, None)
    }

    /// An unexpected internal failure.
    pub fn internal() -> Self {
        Self::new(ErrorCode::Internal, None)
    }

    /// The stable code of this problem.
    pub fn error_code(&self) -> &str {
        self.code
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {}", self.code, detail),
            None => write!(f, "{}", self.code),
        }
    }
}

impl std::error::Error for Problem {}
