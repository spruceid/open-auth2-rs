//! Server-side OAuth 2.0 response types.
#[cfg(feature = "axum")]
mod axum;
mod error;
pub mod metadata;

#[cfg(feature = "axum")]
pub use axum::*;
pub use error::*;
pub use metadata::AuthorizationServerMetadata;
