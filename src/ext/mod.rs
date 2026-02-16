//! OAuth 2.0 protocol extensions.
//!
//! - [`pkce`] — Proof Key for Code Exchange
//!   ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)).
//! - [`rar`] — Rich Authorization Requests
//!   ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html)).
pub mod pkce;
pub mod rar;
