//! HTTP transport layer, content type encoding, and client abstraction.
use http::{HeaderMap, HeaderValue, header};
use serde::Serialize;

use crate::client::OAuth2ClientError;

mod client;

pub use client::*;

/// `Content-Type: application/json` header value.
pub const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");

/// `Content-Type: application/x-www-form-urlencoded` header value.
pub const APPLICATION_X_WWW_FORM_URLENCODED: HeaderValue =
	HeaderValue::from_static("application/x-www-form-urlencoded");

/// Validates that the response `Content-Type` header matches the expected
/// value.
///
/// Returns an error if the header is missing or does not match.
pub fn expect_content_type(
	headers: &HeaderMap,
	expected_value: &HeaderValue,
) -> ::std::result::Result<(), OAuth2ClientError> {
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.ok_or_else(|| OAuth2ClientError::response("missing content type"))?;

	if !content_type
		.as_bytes()
		.starts_with(expected_value.as_bytes())
	{
		Err(OAuth2ClientError::response("unexpected content type"))
	} else {
		Ok(())
	}
}

/// Trait for encoding request bodies with a specific content type.
pub trait ContentType {
	/// The `Content-Type` header value, or `None` for requests with no body.
	const VALUE: Option<HeaderValue>;

	/// Serializes the given value into a byte vector using this content type's
	/// encoding.
	fn encode<T: Serialize>(value: &T) -> Vec<u8>;
}

/// No request body. Used for requests that don't carry a payload.
pub struct NoContent;

impl ContentType for NoContent {
	const VALUE: Option<HeaderValue> = None;

	fn encode<T: Serialize>(_value: &T) -> Vec<u8> {
		Vec::new()
	}
}

/// JSON (`application/json`) content type encoding.
pub struct Json;

impl ContentType for Json {
	const VALUE: Option<HeaderValue> = Some(APPLICATION_JSON);

	fn encode<T: Serialize>(value: &T) -> Vec<u8> {
		serde_json::to_vec(value).unwrap()
	}
}

/// URL-encoded form (`application/x-www-form-urlencoded`) content type
/// encoding.
pub struct WwwFormUrlEncoded;

impl ContentType for WwwFormUrlEncoded {
	const VALUE: Option<HeaderValue> = Some(APPLICATION_X_WWW_FORM_URLENCODED);

	fn encode<T: Serialize>(value: &T) -> Vec<u8> {
		log::debug!("serializing {}", std::any::type_name_of_val(value));
		serde_html_form::to_string(value).unwrap().into_bytes()
	}
}
