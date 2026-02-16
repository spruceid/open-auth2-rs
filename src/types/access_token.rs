use str_newtype::StrNewType;

use crate::{
	client::OAuth2ClientError,
	endpoints::{HttpRequest, RequestBuilder, token::TokenType},
	transport::HttpClient,
};

use super::is_vschar;

/// An OAuth 2.0 access token (borrowed).
///
/// Access tokens are credentials used to access protected resources, as
/// defined in [RFC 6749 Section 1.4](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4).
///
/// # Grammar
///
/// ```abnf
/// access-token = 1*VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(AccessTokenBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct AccessToken(str);

impl AccessToken {
	/// Validates that the given string is a well-formed access token.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed access token.
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

/// Extension wrapper that attaches an access token and token type to a
/// request.
///
/// When used with [`HttpRequest`], the access token is injected into the
/// `Authorization` HTTP header using the format `{token_type} {access_token}`.
pub struct WithAccessToken<'a, Ty, T> {
	/// The token type (e.g. `"Bearer"`).
	pub token_type: &'a Ty,

	/// The access token value.
	pub access_token: &'a AccessToken,

	/// The inner request being extended.
	pub value: T,
}

impl<'a, Ty, T> WithAccessToken<'a, Ty, T> {
	/// Creates a new [`WithAccessToken`] wrapping the given request.
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

impl<'a, E, Ty, T> HttpRequest<E> for WithAccessToken<'a, Ty, T>
where
	T: HttpRequest<E>,
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

/// Extension trait for attaching an access token and token type to a
/// [`RequestBuilder`].
pub trait AddAccessToken<'a, Ty> {
	/// The resulting type after adding the access token.
	type Output;

	/// Wraps the current request in a [`WithAccessToken`] that injects the
	/// `Authorization` header on send.
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
