use crate::{client::OAuth2ClientError, http::HttpClient};

impl HttpClient for reqwest::Client {
	async fn send(
		&self,
		request: http::Request<Vec<u8>>,
	) -> Result<http::Response<Vec<u8>>, OAuth2ClientError> {
		let response = self
			.execute(request.try_into().map_err(OAuth2ClientError::request)?)
			.await
			.map_err(OAuth2ClientError::request)?;

		let mut builder = http::Response::builder().status(response.status());

		#[cfg(not(target_arch = "wasm32"))]
		{
			builder = builder.version(response.version());
		}

		for (name, value) in response.headers().iter() {
			builder = builder.header(name, value);
		}

		builder
			.body(
				response
					.bytes()
					.await
					.map_err(OAuth2ClientError::response)?
					.to_vec(),
			)
			.map_err(OAuth2ClientError::response)
	}
}
