//! OAuth 2.0 client trait and error types.
use serde::de::DeserializeOwned;

use crate::ClientId;

/// An OAuth 2.0 client.
///
/// Implementors represent a registered OAuth 2.0 client with a unique
/// [`ClientId`] and an associated type for deserializing extension parameters
/// included in token responses.
pub trait OAuth2Client {
	/// Additional parameters returned alongside the standard token response
	/// fields.
	///
	/// Use [`NoExtension`](crate::endpoints::NoExtension) when no extra
	/// parameters are expected.
	type TokenParams: DeserializeOwned;

	/// Returns the client identifier.
	fn client_id(&self) -> &ClientId;
}

/// Errors that can occur during an OAuth 2.0 HTTP exchange.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2ClientError {
	/// The HTTP request could not be sent.
	#[error("unable to send request: {0}")]
	Request(String),

	/// The HTTP response could not be received or parsed.
	#[error("unable to receive response: {0}")]
	Response(String),

	/// The server responded with an unexpected HTTP status code.
	#[error("server responded with status code: {0}")]
	ServerError(http::StatusCode),
}

impl OAuth2ClientError {
	/// Creates a [`Request`](Self::Request) error, logging the message before
	/// returning.
	pub fn request(e: impl ToString) -> Self {
		let msg = e.to_string();
		log::error!("request error: {msg}");
		Self::Request(msg)
	}

	/// Creates a [`Response`](Self::Response) error, logging the message
	/// before returning.
	pub fn response(e: impl ToString) -> Self {
		let msg = e.to_string();
		log::error!("response error: {msg}");
		Self::Response(e.to_string())
	}

	/// Creates a [`ServerError`](Self::ServerError) error, logging the status
	/// code before returning.
	pub fn server(status: http::StatusCode) -> Self {
		log::error!("unexpected server response status: {status}");
		Self::ServerError(status)
	}
}
