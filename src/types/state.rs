use std::ops::{Deref, DerefMut};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use str_newtype::StrNewType;

use crate::{
	endpoints::{HttpRequest, RedirectRequest, RequestBuilder},
	transport::HttpClient,
};

use super::is_vschar;

/// An OAuth 2.0 state parameter (borrowed).
///
/// The state parameter is an opaque value used to maintain state between an
/// authorization request and callback, primarily for CSRF protection.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
///
/// # Grammar
///
/// ```abnf
/// state = 1*VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(serde, owned(StateBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash)))]
pub struct State(str);

impl State {
	/// Validates that the given string is a well-formed state value.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed state value.
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

impl StateBuf {
	/// Generates a new random, base64url-encoded 128-bit CSRF token.
	pub fn new_random() -> Self {
		Self::new_random_len(16)
	}

	/// Generates a new random, base64url-encoded CSRF token from `len`
	/// random bytes.
	pub fn new_random_len(len: u32) -> Self {
		let random_bytes: Vec<u8> = (0..len).map(|_| rng().random::<u8>()).collect();
		unsafe { Self::new_unchecked(BASE64_URL_SAFE_NO_PAD.encode(random_bytes)) }
	}
}

/// Wrapper that attaches an optional [`State`] (CSRF token) to a request.
///
/// This is used during the authorization flow to bind the request to the
/// callback, preventing cross-site request forgery attacks.
#[skip_serializing_none]
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stateful<T> {
	/// Opaque value used by the client to maintain state between the request
	/// and callback.
	///
	/// The authorization server includes this value when redirecting the
	/// user-agent back to the client. The parameter *should* be used for
	/// preventing cross-site request forgery.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
	pub state: Option<StateBuf>,

	#[serde(flatten)]
	pub value: T,
}

impl<T> Stateful<T> {
	/// Creates a new [`Stateful`] wrapping the given value with an optional
	/// state token.
	pub fn new(value: T, state: Option<StateBuf>) -> Self {
		Self { state, value }
	}
}

impl<T> Deref for Stateful<T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl<T> DerefMut for Stateful<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.value
	}
}

impl<T> RedirectRequest for Stateful<T>
where
	T: RedirectRequest,
{
	type RequestBody<'b>
		= Stateful<T::RequestBody<'b>>
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_> {
		Stateful::new(self.value.build_query(), self.state.clone())
	}
}

impl<E, T> HttpRequest<E> for Stateful<T>
where
	T: HttpRequest<E>,
{
	type ContentType = T::ContentType;
	type RequestBody<'b>
		= Stateful<T::RequestBody<'b>>
	where
		Self: 'b;
	type Response = T::Response;
	type ResponsePayload = T::ResponsePayload;

	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl crate::transport::HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, crate::client::OAuth2ClientError> {
		self.value
			.build_request(endpoint, http_client)
			.await
			.map(|request| request.map(|value| Stateful::new(value, self.state.clone())))
	}

	fn decode_response(
		&self,
		endpoint: &E,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, crate::client::OAuth2ClientError> {
		self.value.decode_response(endpoint, response)
	}

	async fn process_response(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, crate::client::OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

/// Extension trait for attaching an optional state parameter to a
/// [`RequestBuilder`].
pub trait AddState {
	/// The resulting type after adding the state.
	type Output;

	/// Wraps the current request in a [`Stateful`] with the given state
	/// token.
	fn with_state(self, state: Option<StateBuf>) -> Self::Output;
}

impl<E, T> AddState for RequestBuilder<E, T> {
	type Output = RequestBuilder<E, Stateful<T>>;

	fn with_state(self, state: Option<StateBuf>) -> Self::Output {
		self.map(|value| Stateful::new(value, state))
	}
}
