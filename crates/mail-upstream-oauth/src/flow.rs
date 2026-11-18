//! The upstream OAuth protocol logic.
//!
//! Everything here is protocol work: building the authorization request,
//! exchanging the code, refreshing a token, running the device grant. The
//! decisions — which provider, which scopes, which callback, which
//! principal — belong to [`crate::onboarding`], and this module never
//! makes them.
//!
//! The rules that ADR-0008 and RFC 9700 state are enforced here rather
//! than left to the caller:
//!
//! - the authorization endpoint is HTTPS,
//! - the code exchange always carries the PKCE verifier,
//! - a confidential client authenticates with its secret,
//! - the device grant is only started at a device endpoint the provider
//!   actually advertises,
//! - a provider error code is reported as a code, never as its free-text
//!   description, because a provider may echo the request into it.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::UpstreamOAuthError;
use crate::transport::{OAuthRequest, OAuthResponse, OAuthTransport};

/// The tokens a provider issued.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTokens {
    /// The access token.
    pub access_token: String,
    /// The refresh token, when the provider issued one.
    pub refresh_token: Option<String>,
    /// When the access token expires, in seconds since the epoch.
    pub expires_at: Option<u64>,
    /// The scopes the provider granted.
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for ProviderTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderTokens")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl ProviderTokens {
    /// Whether the access token is known to have expired.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

/// The authorization request that is sent to the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The provider's authorization endpoint.
    pub authorization_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// The registered callback.
    pub redirect_uri: String,
    /// The scope strings to request.
    pub scopes: Vec<String>,
    /// The one-time state.
    pub state: String,
    /// The S256 PKCE challenge.
    pub code_challenge: String,
    /// The issuer, sent as the RFC 9207 `iss` parameter.
    pub issuer: Option<String>,
    /// The resource indicator, when the provider uses one.
    pub resource: Option<String>,
}

/// Build the URL the browser is sent to.
///
/// The URL carries the state and the challenge, which are public by
/// design, and never the verifier.
pub fn build_authorization_url(
    request: &AuthorizationRequest,
) -> Result<String, UpstreamOAuthError> {
    let mut url =
        Url::parse(&request.authorization_endpoint).map_err(|_| UpstreamOAuthError::Protocol {
            reason: "the authorization endpoint is not a URL".to_owned(),
        })?;
    if url.scheme() != "https" {
        return Err(UpstreamOAuthError::Protocol {
            reason: "the authorization endpoint must be https".to_owned(),
        });
    }
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &request.client_id);
        query.append_pair("redirect_uri", &request.redirect_uri);
        query.append_pair("scope", &request.scopes.join(" "));
        query.append_pair("state", &request.state);
        query.append_pair("code_challenge", &request.code_challenge);
        query.append_pair("code_challenge_method", "S256");
        if let Some(issuer) = &request.issuer {
            query.append_pair("iss", issuer);
        }
        if let Some(resource) = &request.resource {
            query.append_pair("resource", resource);
        }
    }
    Ok(url.to_string())
}

/// The exchange of an authorization code for tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchange {
    /// The provider's token endpoint.
    pub token_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// The client secret, for a confidential client.
    pub client_secret: Option<String>,
    /// The callback the code was issued for.
    pub redirect_uri: String,
    /// The authorization code.
    pub code: String,
    /// The PKCE verifier.
    pub code_verifier: String,
    /// The scopes that were requested.
    pub scopes: Vec<String>,
}

/// Exchange an authorization code for tokens.
pub fn exchange_authorization_code(
    transport: &dyn OAuthTransport,
    exchange: &TokenExchange,
    now: u64,
) -> Result<ProviderTokens, UpstreamOAuthError> {
    let mut form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), exchange.code.clone()),
        ("redirect_uri".to_owned(), exchange.redirect_uri.clone()),
        ("client_id".to_owned(), exchange.client_id.clone()),
        ("code_verifier".to_owned(), exchange.code_verifier.clone()),
    ];
    if !exchange.scopes.is_empty() {
        form.push(("scope".to_owned(), exchange.scopes.join(" ")));
    }
    if let Some(secret) = &exchange.client_secret {
        form.push(("client_secret".to_owned(), secret.clone()));
    }
    let request = OAuthRequest::post_form(exchange.token_endpoint.clone(), form)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Accept", "application/json");
    let response = transport
        .send(&request)
        .map_err(|failure| UpstreamOAuthError::Transport {
            reason: failure.reason,
        })?;
    parse_token_response(&response, now)
}

/// The exchange of a refresh token for tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshExchange {
    /// The provider's token endpoint.
    pub token_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// The client secret, for a confidential client.
    pub client_secret: Option<String>,
    /// The refresh token.
    pub refresh_token: String,
    /// The scopes that were granted.
    pub scopes: Vec<String>,
}

/// Exchange a refresh token for tokens.
pub fn refresh_access_token(
    transport: &dyn OAuthTransport,
    exchange: &RefreshExchange,
    now: u64,
) -> Result<ProviderTokens, UpstreamOAuthError> {
    let mut form = vec![
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("refresh_token".to_owned(), exchange.refresh_token.clone()),
        ("client_id".to_owned(), exchange.client_id.clone()),
    ];
    if !exchange.scopes.is_empty() {
        form.push(("scope".to_owned(), exchange.scopes.join(" ")));
    }
    if let Some(secret) = &exchange.client_secret {
        form.push(("client_secret".to_owned(), secret.clone()));
    }
    let request = OAuthRequest::post_form(exchange.token_endpoint.clone(), form)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Accept", "application/json");
    let response = transport
        .send(&request)
        .map_err(|failure| UpstreamOAuthError::Transport {
            reason: failure.reason,
        })?;
    parse_token_response(&response, now)
}

/// Read a token response.
///
/// A provider error is reported by its code alone. The description is
/// dropped because a provider is free to quote the request, and the
/// request is what carries the code.
pub fn parse_token_response(
    response: &OAuthResponse,
    now: u64,
) -> Result<ProviderTokens, UpstreamOAuthError> {
    let body = response
        .json_body()
        .map_err(|_| UpstreamOAuthError::Protocol {
            reason: "the token response is not JSON".to_owned(),
        })?;
    if response.status >= 400 || body.get("error").is_some() {
        let code = body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("invalid_request")
            .to_owned();
        if code == "invalid_grant" {
            return Err(UpstreamOAuthError::InvalidGrant { reason: code });
        }
        return Err(UpstreamOAuthError::Protocol { reason: code });
    }
    let access_token = body
        .get("access_token")
        .and_then(|value| value.as_str())
        .ok_or_else(|| UpstreamOAuthError::Protocol {
            reason: "the token response carries no access token".to_owned(),
        })?
        .to_owned();
    if let Some(token_type) = body.get("token_type").and_then(|value| value.as_str())
        && !token_type.eq_ignore_ascii_case("bearer")
    {
        return Err(UpstreamOAuthError::Protocol {
            reason: format!("the token type {token_type} is not supported"),
        });
    }
    let refresh_token = body
        .get("refresh_token")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let expires_at = body
        .get("expires_in")
        .and_then(|value| value.as_u64())
        .map(|seconds| now.saturating_add(seconds));
    let scopes = body
        .get("scope")
        .and_then(|value| value.as_str())
        .map(|scope| {
            scope
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    Ok(ProviderTokens {
        access_token,
        refresh_token,
        expires_at,
        scopes,
    })
}

/// The device authorization a provider issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    /// The code the client polls with.
    pub device_code: String,
    /// The code the user types.
    pub user_code: String,
    /// Where the user goes.
    pub verification_uri: String,
    /// How long the authorization lives.
    pub expires_in: u64,
    /// The polling interval the provider asks for.
    pub interval: u64,
}

/// The default polling interval of RFC 8628.
pub const DEFAULT_DEVICE_INTERVAL: u64 = 5;

/// Start a device authorization grant.
///
/// The device endpoint must be one the provider advertises. A provider
/// without a device endpoint has no device grant, and this function is
/// never called for it.
pub fn start_device_authorization(
    transport: &dyn OAuthTransport,
    device_endpoint: &str,
    client_id: &str,
    scopes: &[String],
) -> Result<DeviceAuthorization, UpstreamOAuthError> {
    let mut form = vec![("client_id".to_owned(), client_id.to_owned())];
    if !scopes.is_empty() {
        form.push(("scope".to_owned(), scopes.join(" ")));
    }
    let request = OAuthRequest::post_form(device_endpoint.to_owned(), form)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Accept", "application/json");
    let response = transport
        .send(&request)
        .map_err(|failure| UpstreamOAuthError::Transport {
            reason: failure.reason,
        })?;
    if response.status >= 400 {
        return Err(UpstreamOAuthError::Protocol {
            reason: "the device authorization request was refused".to_owned(),
        });
    }
    let body = response
        .json_body()
        .map_err(|_| UpstreamOAuthError::Protocol {
            reason: "the device authorization response is not JSON".to_owned(),
        })?;
    let device_code = body
        .get("device_code")
        .and_then(|value| value.as_str())
        .ok_or_else(|| UpstreamOAuthError::Protocol {
            reason: "the device authorization response carries no device code".to_owned(),
        })?
        .to_owned();
    let user_code = body
        .get("user_code")
        .and_then(|value| value.as_str())
        .ok_or_else(|| UpstreamOAuthError::Protocol {
            reason: "the device authorization response carries no user code".to_owned(),
        })?
        .to_owned();
    let verification_uri = body
        .get("verification_uri")
        .or_else(|| body.get("verification_url"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| UpstreamOAuthError::Protocol {
            reason: "the device authorization response carries no verification URI".to_owned(),
        })?
        .to_owned();
    Ok(DeviceAuthorization {
        device_code,
        user_code,
        verification_uri,
        expires_in: body
            .get("expires_in")
            .and_then(|value| value.as_u64())
            .unwrap_or(600),
        interval: body
            .get("interval")
            .and_then(|value| value.as_u64())
            .unwrap_or(DEFAULT_DEVICE_INTERVAL),
    })
}

/// What one device poll returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    /// The user has not decided yet.
    Pending,
    /// The provider asks for a slower polling rate.
    SlowDown,
    /// The user refused.
    Denied,
    /// The device code expired.
    Expired,
    /// The grant completed.
    Complete(ProviderTokens),
}

/// Poll a device authorization.
///
/// The provider's rate-limit answer is reported as
/// [`DevicePoll::SlowDown`] so the caller slows down instead of retrying
/// at the same rate.
pub fn poll_device_authorization(
    transport: &dyn OAuthTransport,
    token_endpoint: &str,
    client_id: &str,
    device_code: &str,
    now: u64,
) -> Result<DevicePoll, UpstreamOAuthError> {
    let form = vec![
        (
            "grant_type".to_owned(),
            "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
        ),
        ("device_code".to_owned(), device_code.to_owned()),
        ("client_id".to_owned(), client_id.to_owned()),
    ];
    let request = OAuthRequest::post_form(token_endpoint.to_owned(), form)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Accept", "application/json");
    let response = transport
        .send(&request)
        .map_err(|failure| UpstreamOAuthError::Transport {
            reason: failure.reason,
        })?;
    let error = response.json_body().ok().and_then(|body| {
        body.get("error")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    });
    if response.status >= 400 || error.is_some() {
        let code = error.unwrap_or_else(|| "invalid_request".to_owned());
        return match code.as_str() {
            "authorization_pending" => Ok(DevicePoll::Pending),
            "slow_down" => Ok(DevicePoll::SlowDown),
            "access_denied" => Ok(DevicePoll::Denied),
            "expired_token" => Ok(DevicePoll::Expired),
            _ => Err(UpstreamOAuthError::Protocol { reason: code }),
        };
    }
    parse_token_response(&response, now).map(DevicePoll::Complete)
}
