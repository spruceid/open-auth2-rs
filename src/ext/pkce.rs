//! Proof Key for Code Exchange by OAuth Public Clients
//!
//! See: <https://datatracker.ietf.org/doc/html/rfc7636>
use std::{borrow::Cow, str::FromStr};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use str_newtype::StrNewType;

use crate::{
	endpoints::{Redirect, Request, RequestBuilder},
	oauth2_extension,
	util::concat_query,
};

oauth2_extension! {
	#[derive(Debug, Clone, PartialEq, Eq)]
	pub struct WithPkceChallenge {
		pub pkce: PkceCodeChallengeAndMethod
	}
}

impl<T> Request for WithPkceChallenge<T> where T: Request {}

impl<T> Redirect for WithPkceChallenge<T>
where
	T: Redirect,
{
	fn build_query(&self) -> iref::uri::QueryBuf {
		concat_query(self.value.build_query(), &self.pkce)
	}
}

pub trait AddPkceChallenge {
	type Output;

	fn with_pkce_challenge(self, pkce: PkceCodeChallengeAndMethod) -> Self::Output;
}

impl<T> AddPkceChallenge for T
where
	T: RequestBuilder,
{
	type Output = T::Mapped<WithPkceChallenge<T::Request>>;

	fn with_pkce_challenge(self, pkce: PkceCodeChallengeAndMethod) -> Self::Output {
		self.map(|value| WithPkceChallenge::new(value, pkce))
	}
}

/// Code Challenge used for [PKCE](https://tools.ietf.org/html/rfc7636) protection via the
/// `code_challenge` parameter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PkceCodeChallengeAndMethod {
	#[serde(rename = "code_challenge")]
	pub challenge: PkceCodeChallengeBuf,

	#[serde(rename = "code_challenge_method")]
	pub method: PkceCodeChallengeMethod,
}

impl PkceCodeChallengeAndMethod {
	/// Creates a new [`PkceCodeChallengeAndMethod`] from the given verifier and
	/// method.
	pub fn from_code_verifier(
		code_verifier: &PkceCodeVerifier,
		method: PkceCodeChallengeMethod,
	) -> Self {
		Self {
			challenge: method.transform(code_verifier).into_owned(),
			method,
		}
	}

	/// Generate a new random, base64-encoded SHA-256 PKCE code.
	pub fn new_random_sha256() -> (Self, PkceCodeVerifierBuf) {
		Self::new_random_sha256_len(32)
	}

	/// Generate a new random, base64-encoded SHA-256 PKCE challenge code and verifier.
	///
	/// # Arguments
	///
	/// * `len` - Number of random bytes to generate, prior to base64-encoding.
	///   The value must be in the range 32 to 96 inclusive in order to generate a verifier
	///   with a suitable length.
	///
	/// # Panics
	///
	/// This method panics if the resulting PKCE code verifier is not of a suitable length
	/// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
	pub fn new_random_sha256_len(len: u32) -> (Self, PkceCodeVerifierBuf) {
		let code_verifier = PkceCodeVerifierBuf::new_random_len(len);
		(
			Self::from_code_verifier_sha256(&code_verifier),
			code_verifier,
		)
	}

	/// Generate a SHA-256 PKCE code challenge from the supplied PKCE code verifier.
	///
	/// # Panics
	///
	/// This method panics if the supplied PKCE code verifier is not of a suitable length
	/// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
	pub fn from_code_verifier_sha256(code_verifier: &PkceCodeVerifier) -> Self {
		Self::from_code_verifier(code_verifier, PkceCodeChallengeMethod::S256)
	}

	/// Returns the PKCE code challenge as a string.
	pub fn as_str(&self) -> &str {
		&self.challenge
	}

	/// Returns the PKCE code challenge method as a string.
	pub fn method(&self) -> &PkceCodeChallengeMethod {
		&self.method
	}
}

/// Code Challenge Method.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.2>
///
/// # Grammar
///
/// ```abnf
/// code-challenge = 43*128unreserved
/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ALPHA = %x41-5A / %x61-7A
/// DIGIT = %x30-39
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(PkceCodeChallengeBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct PkceCodeChallenge(str);

impl PkceCodeChallenge {
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		validate_verifier_or_challenge(bytes)
	}
}

impl<'a> From<&'a PkceCodeVerifier> for &'a PkceCodeChallenge {
	fn from(value: &'a PkceCodeVerifier) -> Self {
		unsafe {
			// SAFETY: Code challenge and verifier have the same grammar.
			PkceCodeChallenge::new_unchecked(value)
		}
	}
}

#[derive(Debug, thiserror::Error)]
#[error("invalid PKCE `code_challenge_method` value")]
pub struct InvalidPkceCodeChallengeMethod;

pub const PKCE_CODE_CHALLENGE_METHOD_PLAIN: &str = "plain";
pub const PKCE_CODE_CHALLENGE_METHOD_S256: &str = "S256";

/// Code Challenge Method.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PkceCodeChallengeMethod {
	Plain,
	S256,
}

impl PkceCodeChallengeMethod {
	pub fn transform<'a>(&self, code_verifier: &'a PkceCodeVerifier) -> Cow<'a, PkceCodeChallenge> {
		match self {
			Self::Plain => Cow::Borrowed(code_verifier.into()),
			Self::S256 => {
				let digest = Sha256::digest(code_verifier);
				Cow::Owned(PkceCodeChallengeBuf(BASE64_URL_SAFE_NO_PAD.encode(digest)))
			}
		}
	}

	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Plain => PKCE_CODE_CHALLENGE_METHOD_PLAIN,
			Self::S256 => PKCE_CODE_CHALLENGE_METHOD_S256,
		}
	}
}

impl FromStr for PkceCodeChallengeMethod {
	type Err = InvalidPkceCodeChallengeMethod;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			PKCE_CODE_CHALLENGE_METHOD_PLAIN => Ok(Self::Plain),
			PKCE_CODE_CHALLENGE_METHOD_S256 => Ok(Self::S256),
			_ => Err(InvalidPkceCodeChallengeMethod),
		}
	}
}

impl Serialize for PkceCodeChallengeMethod {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.as_str().serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for PkceCodeChallengeMethod {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		String::deserialize(deserializer)?
			.parse()
			.map_err(serde::de::Error::custom)
	}
}

/// Code Verifier.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.1>
///
/// # Grammar
///
/// ```abnf
/// code-verifier = 43*128unreserved
/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ALPHA = %x41-5A / %x61-7A
/// DIGIT = %x30-39
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(PkceCodeVerifierBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct PkceCodeVerifier(str);

impl PkceCodeVerifier {
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		validate_verifier_or_challenge(bytes)
	}
}

impl PkceCodeVerifierBuf {
	/// Generate a new random, base64-encoded PKCE code verifier.
	///
	/// # Arguments
	///
	/// * `len` - Number of random bytes to generate, prior to base64-encoding.
	///   The value must be in the range 32 to 96 inclusive in order to generate a verifier
	///   with a suitable length.
	///
	/// # Panics
	///
	/// This method panics if the resulting PKCE code verifier is not of a suitable length
	/// to comply with [RFC 7636](https://tools.ietf.org/html/rfc7636).
	pub fn new_random_len(len: u32) -> Self {
		// The RFC specifies that the code verifier must have "a minimum length of 43
		// characters and a maximum length of 128 characters".
		// This implies 32-96 octets of random data to be base64 encoded.
		assert!((32..=96).contains(&len));
		let random_bytes: Vec<u8> = (0..len).map(|_| rng().random::<u8>()).collect();
		Self(BASE64_URL_SAFE_NO_PAD.encode(random_bytes))
	}
}

const fn validate_verifier_or_challenge(bytes: &[u8]) -> bool {
	if bytes.len() < 43 || bytes.len() > 128 {
		return false;
	}

	let mut i = 0;

	while i < bytes.len() {
		if bytes[i].is_ascii_alphanumeric() && matches!(bytes[i], b'-' | b'.' | b'_' | b'~') {
			return false;
		}

		i += 1
	}

	true
}
