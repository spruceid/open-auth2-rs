use std::ops::{Deref, DerefMut};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use str_newtype::StrNewType;

use crate::endpoints::{Redirect, Request, RequestBuilder};

use super::is_vschar;

/// State.
///
/// # Grammar
///
/// ```abnf
/// state      = 1*VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(serde, owned(StateBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash)))]
pub struct State(str);

impl State {
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

impl StateBuf {
	/// Generate a new random, base64-encoded 128-bit CSRF token.
	pub fn new_random() -> Self {
		Self::new_random_len(16)
	}

	/// Generate a new random, base64-encoded CSRF token of the specified
	/// length.
	pub fn new_random_len(len: u32) -> Self {
		let random_bytes: Vec<u8> = (0..len).map(|_| rng().random::<u8>()).collect();
		unsafe { Self::new_unchecked(BASE64_URL_SAFE_NO_PAD.encode(random_bytes)) }
	}
}

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

impl<T> Request for Stateful<T> where T: Request {}

impl<T> Redirect for Stateful<T>
where
	T: Redirect,
{
	type RequestBody<'b>
		= Stateful<T::RequestBody<'b>>
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_> {
		Stateful::new(self.value.build_query(), self.state.clone())
	}
}

pub trait AddState {
	type Output;

	fn with_state(self, state: Option<StateBuf>) -> Self::Output;
}

impl<T> AddState for T
where
	T: RequestBuilder,
{
	type Output = T::Mapped<Stateful<T::Request>>;

	fn with_state(self, state: Option<StateBuf>) -> Self::Output {
		self.map(|value| Stateful::new(value, state))
	}
}
