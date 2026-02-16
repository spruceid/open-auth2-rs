use crate::client::OAuth2ClientError;

#[cfg(feature = "reqwest")]
mod reqwest;

/// An asynchronous HTTP client capable of sending raw requests.
///
/// This trait abstracts over the actual HTTP implementation, allowing the
/// library to work with any HTTP client (e.g. `reqwest`). An implementation
/// for [`reqwest::Client`](::reqwest::Client) is provided behind the `reqwest`
/// feature flag.
pub trait HttpClient {
	/// Sends an HTTP request and returns the response.
	///
	/// Both the request body and response body are represented as raw byte
	/// vectors.
	#[allow(async_fn_in_trait)]
	async fn send(
		&self,
		request: http::Request<Vec<u8>>,
	) -> Result<http::Response<Vec<u8>>, OAuth2ClientError>;
}

impl<T> HttpClient for &T
where
	T: HttpClient,
{
	async fn send(
		&self,
		request: http::Request<Vec<u8>>,
	) -> Result<http::Response<Vec<u8>>, OAuth2ClientError> {
		T::send(*self, request).await
	}
}
