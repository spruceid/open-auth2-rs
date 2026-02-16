use str_newtype::StrNewType;

use crate::{
	client::OAuth2ClientError,
	endpoints::{RequestBuilder, SendRequest, token::TokenType},
	transport::HttpClient,
};

use super::is_vschar;

/// Access Token.
///
/// # Grammar
///
/// ```abnf
/// code = 1*VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(AccessTokenBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct AccessToken(str);

impl AccessToken {
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		let mut i = 0;

		while i < bytes.len() {
			if !is_vschar(bytes[i]) {
				return false;
			}

			i += 1
		}

		i > 0
	}
}

pub struct WithAccessToken<'a, Ty, T> {
	pub token_type: &'a Ty,
	pub access_token: &'a AccessToken,
	pub value: T,
}

impl<'a, Ty, T> WithAccessToken<'a, Ty, T> {
	pub fn new(value: T, token_type: &'a Ty, access_token: &'a AccessToken) -> Self {
		Self {
			value,
			token_type,
			access_token,
		}
	}
}

impl<'a, Ty, T> std::ops::Deref for WithAccessToken<'a, Ty, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl<'a, Ty, T> std::borrow::Borrow<T> for WithAccessToken<'a, Ty, T> {
	fn borrow(&self) -> &T {
		&self.value
	}
}

impl<'a, E, Ty, T> SendRequest<E> for WithAccessToken<'a, Ty, T>
where
	T: SendRequest<E>,
	Ty: TokenType,
{
	type ContentType = T::ContentType;
	type RequestBody<'b>
		= T::RequestBody<'b>
	where
		Self: 'b;
	type Response = T::Response;
	type ResponsePayload = T::ResponsePayload;

	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, crate::client::OAuth2ClientError> {
		let mut request = self.value.build_request(endpoint, http_client).await?;
		request.headers_mut().insert(
			http::header::AUTHORIZATION,
			format!("{} {}", self.token_type, self.access_token)
				.try_into()
				.unwrap(),
		);
		Ok(request)
	}

	fn decode_response(
		&self,
		endpoint: &E,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
		self.value.decode_response(endpoint, response)
	}

	async fn process_response(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

pub trait AddAccessToken<'a, Ty> {
	type Output;

	fn with_access_token(self, token_type: &'a Ty, access_token: &'a AccessToken) -> Self::Output;
}

impl<'a, Ty, E, T> AddAccessToken<'a, Ty> for RequestBuilder<E, T>
where
	Ty: 'a,
{
	type Output = RequestBuilder<E, WithAccessToken<'a, Ty, T>>;

	fn with_access_token(self, token_type: &'a Ty, access_token: &'a AccessToken) -> Self::Output {
		self.map(|value| WithAccessToken::new(value, token_type, access_token))
	}
}
