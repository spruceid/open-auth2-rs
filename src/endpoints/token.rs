use std::fmt::Display;

use iref::Uri;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

use crate::{
	AccessTokenBuf, ScopeBuf,
	client::OAuth2ClientError,
	endpoints::{Endpoint, NoExtension, RequestBuilder, SendRequest},
	http::HttpClient,
};

pub struct TokenEndpoint<'a, C> {
	pub client: &'a C,
	pub uri: &'a Uri,
}

impl<'a, C> Clone for TokenEndpoint<'a, C> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<'a, C> Copy for TokenEndpoint<'a, C> {}

impl<'a, C> TokenEndpoint<'a, C> {
	pub fn new(client: &'a C, uri: &'a Uri) -> Self {
		Self { client, uri }
	}

	pub fn begin<T>(self, request: T) -> TokenRequestBuilder<'a, C, T> {
		TokenRequestBuilder::new(self, request)
	}
}

impl<'a, C> Endpoint for TokenEndpoint<'a, C> {
	type Client = C;

	fn client(&self) -> &Self::Client {
		self.client
	}
}

pub struct TokenRequestBuilder<'a, C, T> {
	pub endpoint: TokenEndpoint<'a, C>,
	pub request: T,
}

impl<'a, C, T> TokenRequestBuilder<'a, C, T> {
	pub fn new(endpoint: TokenEndpoint<'a, C>, request: T) -> Self {
		Self { endpoint, request }
	}

	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> TokenRequestBuilder<'a, C, U> {
		TokenRequestBuilder {
			endpoint: self.endpoint,
			request: f(self.request),
		}
	}

	pub async fn send(self, http_client: &impl HttpClient) -> Result<T::Response, OAuth2ClientError>
	where
		T: SendRequest<TokenEndpoint<'a, C>>,
	{
		self.request.send(&self.endpoint, http_client).await
	}
}

impl<'a, C, T> RequestBuilder for TokenRequestBuilder<'a, C, T> {
	type Request = T;
	type Mapped<U> = TokenRequestBuilder<'a, C, U>;

	fn map<U>(self, f: impl FnOnce(Self::Request) -> U) -> Self::Mapped<U> {
		self.map(f)
	}
}

pub trait TokenType: Serialize + DeserializeOwned + Display {}

impl TokenType for String {}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(
	serialize = "T: TokenType, E: Serialize",
	deserialize = "T: TokenType, E: Deserialize<'de>"
))]
pub struct TokenResponse<T: TokenType = String, E = NoExtension> {
	/// access token issued by the authorization server.
	pub access_token: AccessTokenBuf,

	/// The type of the token issued as described in Section 7.1.  Value is case insensitive.
	pub token_type: T,

	/// Lifetime in seconds of the access token.
	///
	/// For example, the value "3600" denotes that the access token will expire
	/// in one hour from the time the response was generated.
	///
	/// Setting this value is *recommended*.
	///
	/// If omitted, the authorization server *should* provide the expiration
	/// time via other means or document the default value.
	pub expires_in: Option<u64>,

	/// The refresh token, which can be used to obtain new access tokens using the same authorization grant as described in Section 6.
	pub refresh_token: Option<String>,

	/// Scope of the access token as described by Section 3.3.
	///
	/// Optional if identical to the scope requested by the client.
	pub scope: Option<ScopeBuf>,

	/// Extension.
	#[serde(flatten)]
	pub ext: E,
}

impl<T, E> TokenResponse<T, E>
where
	T: TokenType,
{
	pub fn new(access_token: AccessTokenBuf, token_type: T, ext: E) -> Self {
		Self {
			access_token,
			token_type,
			expires_in: None,
			refresh_token: None,
			scope: None,
			ext,
		}
	}
}
