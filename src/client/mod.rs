use serde::de::DeserializeOwned;

use crate::ClientId;

pub trait OAuth2Client {
	type TokenParams: DeserializeOwned;

	fn client_id(&self) -> &ClientId;
}

#[derive(Debug, thiserror::Error)]
pub enum OAuth2ClientError {
	#[error("unable to send request: {0}")]
	Request(String),

	#[error("unable to receive response: {0}")]
	Response(String),

	#[error("server responded with status code: {0}")]
	ServerError(http::StatusCode),
}

impl OAuth2ClientError {
	pub fn request(e: impl ToString) -> Self {
		let msg = e.to_string();
		log::error!("request error: {msg}");
		Self::Request(msg)
	}

	pub fn response(e: impl ToString) -> Self {
		let msg = e.to_string();
		log::error!("response error: {msg}");
		Self::Response(e.to_string())
	}

	pub fn server(status: http::StatusCode) -> Self {
		log::error!("unexpected server response status: {status}");
		Self::ServerError(status)
	}
}
