pub use http::*;

mod client;

pub use client::*;

use crate::client::OAuth2ClientError;

pub const APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");

pub const APPLICATION_X_WWW_FORM_URLENCODED: HeaderValue =
	HeaderValue::from_static("application/x-www-form-urlencoded");

pub fn expect_content_type(
	headers: &HeaderMap,
	expected_value: &HeaderValue,
) -> ::std::result::Result<(), OAuth2ClientError> {
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.ok_or_else(|| OAuth2ClientError::response("missing content type"))?;

	if content_type != expected_value {
		Err(OAuth2ClientError::response("unexpected content type"))
	} else {
		Ok(())
	}
}
