//! OAuth 2.0 grant type implementations.
//!
//! Each submodule implements a specific authorization grant type:
//!
//! - [`authorization_code`] — Authorization Code Grant
//!   ([RFC 6749 Section 4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)).
//! - [`pre_authorized_code`] — Pre-Authorized Code Grant
//!   ([OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)).
pub mod authorization_code;
pub mod pre_authorized_code;
