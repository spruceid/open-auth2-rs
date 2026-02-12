pub use http::*;

mod client;

pub use client::*;
use serde::Serialize;

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

	if !content_type
		.as_bytes()
		.starts_with(expected_value.as_bytes())
	{
		Err(OAuth2ClientError::response("unexpected content type"))
	} else {
		Ok(())
	}
}

pub trait ContentType {
	const VALUE: Option<HeaderValue>;

	fn encode<T: Serialize>(value: &T) -> Vec<u8>;
}

pub struct NoContent;

impl ContentType for NoContent {
	const VALUE: Option<HeaderValue> = None;

	fn encode<T: Serialize>(_value: &T) -> Vec<u8> {
		Vec::new()
	}
}

pub struct Json;

impl ContentType for Json {
	const VALUE: Option<HeaderValue> = Some(APPLICATION_JSON);

	fn encode<T: Serialize>(value: &T) -> Vec<u8> {
		serde_json::to_vec(value).unwrap()
	}
}

pub struct WwwFormUrlEncoded;

impl ContentType for WwwFormUrlEncoded {
	const VALUE: Option<HeaderValue> = Some(APPLICATION_X_WWW_FORM_URLENCODED);

	fn encode<T: Serialize>(value: &T) -> Vec<u8> {
		log::debug!("serializing {}", std::any::type_name_of_val(value));
		serde_html_form::to_string(value).unwrap().into_bytes()
	}
}
