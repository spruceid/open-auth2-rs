use iref::Uri;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

use crate::ScopeBuf;

pub struct TokenEndpoint<'a, C> {
	pub client: &'a C,
	pub uri: &'a Uri,
}

pub struct TokenRequestBuilder<'a, C, T> {
	pub endpoint: TokenEndpoint<'a, C>,
	pub value: T,
}

impl<'a, C, T> TokenRequestBuilder<'a, C, T> {
	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> TokenRequestBuilder<'a, C, U> {
		TokenRequestBuilder {
			endpoint: self.endpoint,
			value: f(self.value),
		}
	}
}

pub trait TokenType: Serialize + DeserializeOwned {}

impl TokenType for String {}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound = "T: TokenType")]
pub struct TokenResponse<T: TokenType = String> {
	/// access token issued by the authorization server.
	pub access_token: String,

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
}
