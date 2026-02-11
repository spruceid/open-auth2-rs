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
		Self::Request(e.to_string())
	}

	pub fn response(e: impl ToString) -> Self {
		Self::Response(e.to_string())
	}
}

pub trait OAuth2Client {
	fn client_id(&self) -> &str;
}
