//! OAuth 2.0 token endpoint.
//!
//! See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.2>
use std::fmt::Display;

use iref::Uri;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

use crate::{
	AccessTokenBuf, ScopeBuf, client::OAuth2Client, endpoints::Endpoint, util::NoExtension,
};

/// The OAuth 2.0 token endpoint.
///
/// This endpoint is used by the client to exchange an authorization grant for
/// an access token, as defined in
/// [RFC 6749 Section 3.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2).
pub struct TokenEndpoint<'a, C> {
	/// The OAuth 2.0 client.
	pub client: &'a C,

	/// The token endpoint URI.
	pub uri: &'a Uri,
}

impl<'a, C> Clone for TokenEndpoint<'a, C> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<'a, C> Copy for TokenEndpoint<'a, C> {}

impl<'a, C> TokenEndpoint<'a, C> {
	/// Creates a new token endpoint for the given client and URI.
	pub fn new(client: &'a C, uri: &'a Uri) -> Self {
		Self { client, uri }
	}

	// pub fn begin<T>(self, request: T) -> TokenRequestBuilder<'a, C, T> {
	// 	TokenRequestBuilder::new(self, request)
	// }
}

impl<'a, C> Endpoint for TokenEndpoint<'a, C>
where
	C: OAuth2Client,
{
	type Client = C;

	fn client(&self) -> &Self::Client {
		self.client
	}

	fn uri(&self) -> &Uri {
		self.uri
	}
}

/// Marker trait for OAuth 2.0 token types (e.g. `"Bearer"`, `"DPoP"`).
///
/// Token types must be serializable, deserializable, and displayable so they
/// can be included in both HTTP headers and JSON responses.
pub trait TokenType: Serialize + DeserializeOwned + Display {}

impl TokenType for String {}

/// Successful response from the token endpoint.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.1>
///
/// The type parameters allow customizing the token type string and any
/// extension fields returned by the authorization server. Use
/// [`NoExtension`] when no extra fields are expected.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound(
	serialize = "T: TokenType, E: Serialize",
	deserialize = "T: TokenType, E: Deserialize<'de>"
))]
pub struct TokenResponse<T: TokenType = String, E = NoExtension> {
	/// The access token issued by the authorization server.
	pub access_token: AccessTokenBuf,

	/// The type of the token issued (e.g. `"Bearer"`), as described in
	/// [Section 7.1](https://datatracker.ietf.org/doc/html/rfc6749#section-7.1).
	/// Value is case insensitive.
	pub token_type: T,

	/// Lifetime in seconds of the access token.
	///
	/// For example, the value `3600` denotes that the access token will
	/// expire in one hour from the time the response was generated.
	///
	/// Setting this value is *recommended*.
	///
	/// If omitted, the authorization server *should* provide the expiration
	/// time via other means or document the default value.
	pub expires_in: Option<u64>,

	/// The refresh token, which can be used to obtain new access tokens
	/// using the same authorization grant as described in
	/// [Section 6](https://datatracker.ietf.org/doc/html/rfc6749#section-6).
	pub refresh_token: Option<String>,

	/// The scope of the access token as described by
	/// [Section 3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
	///
	/// Optional if identical to the scope requested by the client.
	pub scope: Option<ScopeBuf>,

	/// Extension fields returned by the authorization server.
	#[serde(flatten)]
	pub ext: E,
}

impl<T, E> TokenResponse<T, E>
where
	T: TokenType,
{
	/// Creates a new token response with the required fields.
	///
	/// Optional fields (`expires_in`, `refresh_token`, `scope`) default to
	/// `None`.
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
