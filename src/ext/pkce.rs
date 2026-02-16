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
	endpoints::{HttpRequest, RedirectRequest, RequestBuilder},
	transport::HttpClient,
};

/// Extension wrapper that attaches a PKCE code challenge and method to a
/// request.
///
/// Used during the authorization phase to send the `code_challenge` and
/// `code_challenge_method` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WithPkceChallenge<T> {
	/// The PKCE code challenge and method.
	#[serde(flatten)]
	pub pkce: PkceCodeChallengeAndMethod,

	/// The inner request being extended.
	#[serde(flatten)]
	pub value: T,
}

impl<T> WithPkceChallenge<T> {
	/// Creates a new [`WithPkceChallenge`] wrapping the given request.
	pub fn new(value: T, pkce: PkceCodeChallengeAndMethod) -> Self {
		Self { value, pkce }
	}
}

impl<T> std::ops::Deref for WithPkceChallenge<T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl<T> std::borrow::Borrow<T> for WithPkceChallenge<T> {
	fn borrow(&self) -> &T {
		&self.value
	}
}

impl<T> RedirectRequest for WithPkceChallenge<T>
where
	T: RedirectRequest,
{
	type RequestBody<'b>
		= WithPkceChallenge<T::RequestBody<'b>>
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_> {
		WithPkceChallenge::new(self.value.build_query(), self.pkce.clone())
	}
}

impl<E, T> HttpRequest<E> for WithPkceChallenge<T>
where
	T: HttpRequest<E>,
{
	type ContentType = T::ContentType;
	type RequestBody<'b>
		= WithPkceChallenge<T::RequestBody<'b>>
	where
		Self: 'b;
	type Response = T::Response;
	type ResponsePayload = T::ResponsePayload;

	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, crate::client::OAuth2ClientError> {
		self.value
			.build_request(endpoint, http_client)
			.await
			.map(|request| request.map(|value| WithPkceChallenge::new(value, self.pkce.clone())))
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
		http_client: &impl crate::transport::HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, crate::client::OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

/// Extension trait for attaching a PKCE code challenge to a
/// [`RequestBuilder`].
pub trait AddPkceChallenge {
	/// The resulting type after adding the PKCE challenge.
	type Output;

	/// Wraps the current request with PKCE challenge parameters.
	fn with_pkce_challenge(self, pkce: PkceCodeChallengeAndMethod) -> Self::Output;
}

impl<E, T> AddPkceChallenge for RequestBuilder<E, T> {
	type Output = RequestBuilder<E, WithPkceChallenge<T>>;

	fn with_pkce_challenge(self, pkce: PkceCodeChallengeAndMethod) -> Self::Output {
		self.map(|value| WithPkceChallenge::new(value, pkce))
	}
}

/// Extension wrapper that attaches a PKCE code verifier to a token request.
///
/// Used during the token exchange phase to send the `code_verifier`
/// parameter, proving possession of the original challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WithPkceVerifier<'a, T> {
	/// The PKCE code verifier.
	pub code_verifier: &'a PkceCodeVerifier,

	/// The inner request being extended.
	#[serde(flatten)]
	pub value: T,
}

impl<'a, T> WithPkceVerifier<'a, T> {
	/// Creates a new [`WithPkceVerifier`] wrapping the given request.
	pub fn new(value: T, code_verifier: &'a PkceCodeVerifier) -> Self {
		Self {
			value,
			code_verifier,
		}
	}
}

impl<'a, T> std::ops::Deref for WithPkceVerifier<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl<'a, T> std::borrow::Borrow<T> for WithPkceVerifier<'a, T> {
	fn borrow(&self) -> &T {
		&self.value
	}
}

impl<'a, T, E> HttpRequest<E> for WithPkceVerifier<'a, T>
where
	T: HttpRequest<E>,
{
	type ContentType = T::ContentType;
	type RequestBody<'b>
		= WithPkceVerifier<'a, T::RequestBody<'b>>
	where
		Self: 'b;
	type Response = T::Response;
	type ResponsePayload = T::ResponsePayload;

	async fn build_request<'b>(
		&'b self,
		endpoint: &E,
		http_client: &impl crate::transport::HttpClient,
	) -> Result<http::Request<Self::RequestBody<'b>>, crate::client::OAuth2ClientError> {
		Ok(self
			.value
			.build_request(endpoint, http_client)
			.await?
			.map(|value| WithPkceVerifier::new(value, self.code_verifier)))
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
		http_client: &impl crate::transport::HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, crate::client::OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

impl<'a, T> RedirectRequest for WithPkceVerifier<'a, T>
where
	T: RedirectRequest,
{
	type RequestBody<'b>
		= WithPkceVerifier<'a, T::RequestBody<'b>>
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_> {
		WithPkceVerifier::new(self.value.build_query(), self.code_verifier)
	}
}

/// Extension trait for attaching a PKCE code verifier to a
/// [`RequestBuilder`].
pub trait AddPkceVerifier<'a> {
	/// The resulting type after adding the PKCE verifier.
	type Output;

	/// Wraps the current request with the PKCE code verifier.
	fn with_pkce_verifier(self, pkce_verifier: &'a PkceCodeVerifier) -> Self::Output;
}

impl<'a, E, T> AddPkceVerifier<'a> for RequestBuilder<E, T> {
	type Output = RequestBuilder<E, WithPkceVerifier<'a, T>>;

	fn with_pkce_verifier(self, pkce_verifier: &'a PkceCodeVerifier) -> Self::Output {
		self.map(|value| WithPkceVerifier::new(value, pkce_verifier))
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
	/// Validates that the given string is a well-formed PKCE code challenge.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed PKCE code
	/// challenge.
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

/// Error returned when parsing an invalid PKCE code challenge method string.
#[derive(Debug, thiserror::Error)]
#[error("invalid PKCE `code_challenge_method` value")]
pub struct InvalidPkceCodeChallengeMethod;

/// String representation of the `plain` code challenge method.
pub const PKCE_CODE_CHALLENGE_METHOD_PLAIN: &str = "plain";

/// String representation of the `S256` code challenge method.
pub const PKCE_CODE_CHALLENGE_METHOD_S256: &str = "S256";

/// PKCE code challenge method.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7636#section-4.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PkceCodeChallengeMethod {
	/// The code challenge is the plain code verifier (not recommended).
	Plain,

	/// The code challenge is the BASE64URL-encoded SHA-256 hash of the
	/// code verifier.
	S256,
}

impl PkceCodeChallengeMethod {
	/// Transforms a code verifier into a code challenge using this method.
	pub fn transform<'a>(&self, code_verifier: &'a PkceCodeVerifier) -> Cow<'a, PkceCodeChallenge> {
		match self {
			Self::Plain => Cow::Borrowed(code_verifier.into()),
			Self::S256 => {
				let digest = Sha256::digest(code_verifier);
				Cow::Owned(PkceCodeChallengeBuf(BASE64_URL_SAFE_NO_PAD.encode(digest)))
			}
		}
	}

	/// Returns the string representation of this method.
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
	/// Validates that the given string is a well-formed PKCE code verifier.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed PKCE code
	/// verifier.
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
		if !bytes[i].is_ascii_alphanumeric() && !matches!(bytes[i], b'-' | b'.' | b'_' | b'~') {
			return false;
		}

		i += 1
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	// 43 characters of valid unreserved chars.
	const MIN_VALID: &str = "abcdefghijklmnopqrstuvwxyz01234567890123456";

	// --- PkceCodeChallenge ---

	#[test]
	fn valid_challenge() {
		assert!(PkceCodeChallenge::new(MIN_VALID).is_ok());
	}

	#[test]
	fn challenge_too_short() {
		// 42 characters — one below minimum.
		assert!(PkceCodeChallenge::new(&MIN_VALID[..42]).is_err());
	}

	#[test]
	fn challenge_too_long() {
		// 129 characters — one above maximum.
		let long = "a".repeat(129);
		assert!(PkceCodeChallenge::new(&long).is_err());
	}

	#[test]
	fn challenge_max_length() {
		let max = "a".repeat(128);
		assert!(PkceCodeChallenge::new(&max).is_ok());
	}

	#[test]
	fn challenge_allows_unreserved_chars() {
		// Alphanumeric + `-` `.` `_` `~`
		let s = "abcdefghijklmnopqrstuvwxyz-._~ABCDEFGHIJKLMN";
		assert!(PkceCodeChallenge::new(s).is_ok());
	}

	#[test]
	fn challenge_rejects_invalid_chars() {
		let mut bytes = MIN_VALID.as_bytes().to_vec();
		bytes[0] = b' ';
		let s = String::from_utf8(bytes).unwrap();
		assert!(PkceCodeChallenge::new(&s).is_err());
	}

	#[test]
	fn challenge_rejects_plus() {
		let mut bytes = MIN_VALID.as_bytes().to_vec();
		bytes[0] = b'+';
		let s = String::from_utf8(bytes).unwrap();
		assert!(PkceCodeChallenge::new(&s).is_err());
	}

	// --- PkceCodeVerifier ---

	#[test]
	fn valid_verifier() {
		assert!(PkceCodeVerifier::new(MIN_VALID).is_ok());
	}

	#[test]
	fn verifier_too_short() {
		assert!(PkceCodeVerifier::new(&MIN_VALID[..42]).is_err());
	}

	#[test]
	fn verifier_too_long() {
		let long = "a".repeat(129);
		assert!(PkceCodeVerifier::new(&long).is_err());
	}

	#[test]
	fn random_verifier_is_valid() {
		let verifier = PkceCodeVerifierBuf::new_random_len(32);
		assert!(PkceCodeVerifier::new(verifier.as_str()).is_ok());
	}

	#[test]
	fn random_verifier_max_len_is_valid() {
		let verifier = PkceCodeVerifierBuf::new_random_len(96);
		assert!(PkceCodeVerifier::new(verifier.as_str()).is_ok());
	}

	// --- PkceCodeChallengeMethod ---

	#[test]
	fn parse_challenge_method() {
		assert_eq!(
			"S256".parse::<PkceCodeChallengeMethod>().unwrap(),
			PkceCodeChallengeMethod::S256,
		);
		assert_eq!(
			"plain".parse::<PkceCodeChallengeMethod>().unwrap(),
			PkceCodeChallengeMethod::Plain,
		);
		assert!("invalid".parse::<PkceCodeChallengeMethod>().is_err());
	}

	#[test]
	fn challenge_method_as_str() {
		assert_eq!(PkceCodeChallengeMethod::S256.as_str(), "S256");
		assert_eq!(PkceCodeChallengeMethod::Plain.as_str(), "plain");
	}

	// --- PkceCodeChallengeAndMethod ---

	#[test]
	fn sha256_challenge_is_valid() {
		let (challenge, _verifier) = PkceCodeChallengeAndMethod::new_random_sha256();
		assert_eq!(challenge.method, PkceCodeChallengeMethod::S256);
		assert!(PkceCodeChallenge::new(challenge.as_str()).is_ok());
	}

	#[test]
	fn plain_challenge_equals_verifier() {
		let verifier = PkceCodeVerifierBuf::new_random_len(32);
		let challenge = PkceCodeChallengeAndMethod::from_code_verifier(
			&verifier,
			PkceCodeChallengeMethod::Plain,
		);
		assert_eq!(challenge.as_str(), verifier.as_str());
	}
}
