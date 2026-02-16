//! Implementation of the [OAuth 2.0 Authorization Framework][rfc6749].
//!
//! This crate provides building blocks for implementing OAuth 2.0 clients and
//! servers, following the specifications defined in [RFC 6749][rfc6749] and
//! related extensions:
//!
//! - [RFC 7636][rfc7636] — Proof Key for Code Exchange (PKCE)
//! - [RFC 9126][rfc9126] — Pushed Authorization Requests (PAR)
//! - [RFC 9396][rfc9396] — Rich Authorization Requests (RAR)
//! - [OpenID4VCI][oid4vci] — Pre-Authorized Code Grant
//!
//! # Modules
//!
//! - [`client`] — OAuth 2.0 client trait and error types.
//! - [`endpoints`] — Endpoint abstractions (authorization, token, PAR).
//! - [`ext`] — Protocol extensions (PKCE, RAR).
//! - [`grant`] — Grant type implementations (authorization code,
//!   pre-authorized code).
//! - [`server`] — Server-side response types.
//! - [`transport`] — HTTP transport layer and content type encoding.
//! - [`util`] — URI query string utilities.
//!
//! Core OAuth 2.0 types ([`AccessToken`], [`ClientId`], [`Code`], [`Scope`],
//! [`State`], etc.) are re-exported at the crate root.
//!
//! [rfc6749]: https://datatracker.ietf.org/doc/html/rfc6749
//! [rfc7636]: https://datatracker.ietf.org/doc/html/rfc7636
//! [rfc9126]: https://www.rfc-editor.org/rfc/rfc9126.html
//! [rfc9396]: https://www.rfc-editor.org/rfc/rfc9396.html
//! [oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
#[cfg(feature = "reqwest")]
pub use reqwest;

pub use http;

pub mod client;
pub mod endpoints;
pub mod ext;
pub mod grant;
pub mod server;
pub mod transport;
mod types;
pub mod util;

pub use types::*;
