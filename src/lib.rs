//! OAuth 2.0 Authorization Framework implementation.
//!
//! See: <https://datatracker.ietf.org/doc/html/rfc6749>
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
