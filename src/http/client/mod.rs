use crate::client::OAuth2ClientError;

#[cfg(feature = "reqwest")]
mod reqwest;

pub trait HttpClient {
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
