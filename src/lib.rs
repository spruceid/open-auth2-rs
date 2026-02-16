//! This crate provides building blocks for implementing OAuth 2.0 clients and
//! servers, following the specifications defined in [RFC 6749][rfc6749] and
//! related extensions:
//!
//! - [RFC 7636][rfc7636] — Proof Key for Code Exchange (PKCE)
//! - [RFC 9126][rfc9126] — Pushed Authorization Requests (PAR)
//! - [RFC 9396][rfc9396] — Rich Authorization Requests (RAR)
//! - [OpenID4VCI][oid4vci] — Pre-Authorized Code Grant
//!
//! It is meant to provide a highly modular architecture to accommodate the
//! numerous extensions to the OAuth 2.0 framework.
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
//! # Client usage
//!
//! The following shows how to set up a client, build an authorization URL
//! with PKCE, and exchange the resulting code for a token.
//!
//! ```rust,no_run
//! use open_auth2::{
//!     ClientId, StateBuf,
//!     AddState,
//!     client::OAuth2Client,
//!     endpoints::{authorization::AuthorizationEndpoint, token::{TokenEndpoint, TokenResponse}},
//!     ext::pkce::{AddPkceChallenge, AddPkceVerifier, PkceCodeChallengeAndMethod},
//!     transport::HttpClient,
//!     client_id, code
//! };
//!
//! // 1. Define your client.
//! struct MyClient;
//!
//! impl OAuth2Client for MyClient {
//!     type TokenResponse = TokenResponse;
//!
//!     fn client_id(&self) -> &ClientId {
//!         client_id!("my-client-id")
//!     }
//! }
//!
//! async fn run(http_client: &impl HttpClient) -> Result<(), Box<dyn std::error::Error>> {
//!     let client = MyClient;
//!     let auth_uri = iref::Uri::new("https://auth.example.com/authorize")?;
//!     let token_uri = iref::Uri::new("https://auth.example.com/token")?;
//!
//!     // 2. Generate PKCE challenge and state.
//!     let (pkce_challenge, pkce_verifier) = PkceCodeChallengeAndMethod::new_random_sha256();
//!     let state = StateBuf::new_random();
//!
//!     // 3. Build the authorization redirect URL.
//!     let authorize_url = AuthorizationEndpoint::new(&client, auth_uri)
//!         .authorize_url(None, None)
//!         .with_state(Some(state))
//!         .with_pkce_challenge(pkce_challenge)
//!         .into_redirect_uri();
//!
//!     println!("Open in browser: {authorize_url}");
//!
//!     // 4. After the user is redirected back with a `code`, exchange it.
//!     let code = code!("received-code").to_owned();
//!
//!     let token_response = TokenEndpoint::new(&client, token_uri)
//!         .exchange_code(code, None)
//!         .with_pkce_verifier(&pkce_verifier)
//!         .send(http_client)
//!         .await?;
//!
//!     println!("Access token: {}", token_response.access_token);
//!     Ok(())
//! }
//! ```
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
