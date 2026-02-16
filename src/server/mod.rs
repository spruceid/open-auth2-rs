//! Server-side OAuth 2.0 response types.
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[cfg(feature = "axum")]
mod axum;
pub mod metadata;

#[cfg(feature = "axum")]
pub use axum::*;
pub use metadata::AuthorizationServerMetadata;

/// An OAuth 2.0 error response.
///
/// This is the standard error format returned by the authorization server
/// when a request fails, as defined in
/// [RFC 6749 Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ErrorResponse<T = String> {
	/// A single error code string.
	pub error: T,

	/// Human-readable text providing additional information about the error.
	pub error_description: Option<String>,

	/// A URI identifying a human-readable web page with information about
	/// the error.
	pub error_uri: Option<UriBuf>,
}

impl<T> ErrorResponse<T> {
	/// Creates a new error response.
	pub fn new(error: T, error_description: Option<String>, error_uri: Option<UriBuf>) -> Self {
		Self {
			error,
			error_description,
			error_uri,
		}
	}
}

/// Result type that deserializes as either a success payload or an
/// [`ErrorResponse`].
///
/// Uses `#[serde(untagged)]` to transparently handle both cases from a
/// single JSON response body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerResult<T, E = String> {
	/// The request succeeded.
	Ok(T),

	/// The server returned an error.
	Err(ErrorResponse<E>),
}
