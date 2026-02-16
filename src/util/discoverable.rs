use iref::{Uri, UriBuf, UriRef};
use serde::de::DeserializeOwned;

use crate::{
	client::OAuth2ClientError,
	http,
	transport::{APPLICATION_JSON, HttpClient, expect_content_type},
};

pub trait Discoverable: DeserializeOwned {
	const WELL_KNOWN_URI_REF: &UriRef;

	fn validate(&self, base_url: &Uri) -> Result<(), OAuth2ClientError>;

	#[allow(async_fn_in_trait)]
	async fn discover(
		http_client: &impl HttpClient,
		base_url: &Uri,
	) -> Result<Self, OAuth2ClientError> {
		let discovery_url = well_known_uri(base_url, Self::WELL_KNOWN_URI_REF);
		let discovery_request = discovery_request(&discovery_url);
		let http_response = http_client.send(discovery_request).await?;
		discovery_response(base_url, http_response)
	}
}

fn well_known_uri(base_url: &Uri, well_known: &UriRef) -> UriBuf {
	let mut result = UriBuf::from_scheme(base_url.scheme().to_owned());
	result.set_authority(base_url.authority());

	let mut path = result.path_mut();
	for s in well_known.path() {
		path.push(s);
	}

	for s in base_url.path() {
		path.push(s);
	}

	result.set_query(base_url.query());
	result.set_fragment(base_url.fragment());

	result
}

fn discovery_request(discovery_url: &Uri) -> http::Request<Vec<u8>> {
	http::Request::builder()
		.uri(discovery_url.to_string())
		.method(http::Method::GET)
		.header(http::header::ACCEPT, APPLICATION_JSON)
		.body(Vec::new())
		// SAFETY: discovery query is always valid.
		.unwrap()
}

fn discovery_response<T: Discoverable>(
	base_url: &Uri,
	discovery_response: http::Response<Vec<u8>>,
) -> Result<T, OAuth2ClientError> {
	let status = discovery_response.status();
	if status != http::StatusCode::OK {
		return Err(OAuth2ClientError::ServerError(status));
	}

	expect_content_type(discovery_response.headers(), &APPLICATION_JSON)?;

	let metadata: T =
		serde_json::from_slice(discovery_response.body()).map_err(OAuth2ClientError::response)?;
	metadata.validate(base_url)?;

	Ok(metadata)
}

#[cfg(test)]
mod tests {
	use iref::{uri, uri_ref};

	use super::*;

	#[test]
	fn test_well_known_uri1() {
		let result = well_known_uri(
			uri!("https://issuer.example.com/tenant"),
			uri_ref!("/.well-known/openid-credential-issuer"),
		);

		assert_eq!(
			result,
			uri!("https://issuer.example.com/.well-known/openid-credential-issuer/tenant")
		)
	}

	#[test]
	fn test_well_known_uri2() {
		let result = well_known_uri(
			uri!("https://issuer.example.com"),
			uri_ref!("/.well-known/openid-credential-issuer"),
		);

		assert_eq!(
			result,
			uri!("https://issuer.example.com/.well-known/openid-credential-issuer")
		)
	}
}
