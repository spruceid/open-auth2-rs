use iref::{Uri, UriBuf, uri_ref};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
	// authorization::oauth2::{
	// 	client_attestation::ClientAttestationServerParams, dpop::DpopServerParams,
	// },
	ScopeBuf,
	client::OAuth2ClientError,
	ext::pkce::PkceCodeChallengeMethod,
	util::{Discoverable, NoExtension}, // util::discoverable::Discoverable,
};

/// Authorization Server Metadata.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc8414>
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationServerMetadata<P = NoExtension> {
	pub issuer: UriBuf,

	pub authorization_endpoint: Option<UriBuf>,

	pub token_endpoint: Option<UriBuf>,

	pub jwks_uri: Option<UriBuf>,

	pub registration_endpoint: Option<UriBuf>,

	pub scopes_supported: Option<Vec<ScopeBuf>>,

	/// Note: this type is required in the core specification, but made optional
	/// by some extensions.
	pub response_types_supported: Option<Vec<String>>,

	#[serde(default = "default_response_modes_supported")]
	pub response_modes_supported: Vec<String>,

	#[serde(default = "default_grant_types_supported")]
	pub grant_types_supported: Vec<GrantType>,

	pub revocation_endpoint: Option<UriBuf>,

	pub introspection_endpoint: Option<UriBuf>,

	pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

	#[serde(flatten)]
	pub extra: P,
}

impl<P> AuthorizationServerMetadata<P> {
	pub fn new(issuer: UriBuf) -> Self
	where
		P: Default,
	{
		Self {
			issuer,
			authorization_endpoint: None,
			token_endpoint: None,
			jwks_uri: Default::default(),
			registration_endpoint: Default::default(),
			scopes_supported: Default::default(),
			response_types_supported: Default::default(),
			response_modes_supported: default_response_modes_supported(),
			grant_types_supported: default_grant_types_supported(),
			revocation_endpoint: Default::default(),
			introspection_endpoint: Default::default(),
			code_challenge_methods_supported: Default::default(),
			extra: Default::default(),
		}
	}

	pub fn with_authorization_endpoint(self, authorization_endpoint: UriBuf) -> Self {
		Self {
			authorization_endpoint: Some(authorization_endpoint),
			..self
		}
	}

	pub fn with_token_endpoint(self, token_endpoint: UriBuf) -> Self {
		Self {
			token_endpoint: Some(token_endpoint),
			..self
		}
	}
}

#[derive(Debug, thiserror::Error)]
#[error("invalid authorization server metadata")]
pub struct InvalidAuthorizationServerMetadata;

impl<T> Discoverable for AuthorizationServerMetadata<T>
where
	T: DeserializeOwned,
{
	const WELL_KNOWN_URI_REF: &iref::UriRef = uri_ref!(".well-known/oauth-authorization-server");

	fn validate(&self, base_url: &Uri) -> Result<(), OAuth2ClientError> {
		if self.issuer == base_url {
			Ok(())
		} else {
			Err(OAuth2ClientError::response(
				"invalid authorization server metadata issuer",
			))
		}
	}
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
	AuthorizationCode,
	Implicit,
	#[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
	PreAuthorizedCode,
	#[serde(untagged)]
	Extension(String),
}

pub fn default_response_modes_supported() -> Vec<String> {
	vec!["query".to_owned(), "fragment".to_owned()]
}

pub fn default_grant_types_supported() -> Vec<GrantType> {
	vec![GrantType::AuthorizationCode, GrantType::Implicit]
}

#[cfg(feature = "axum")]
mod axum {
	use crate::transport::APPLICATION_JSON;
	use ::axum::{
		body::Body,
		http::{StatusCode, header::CONTENT_TYPE},
		response::{IntoResponse, Response},
	};

	use super::*;

	impl<T> IntoResponse for AuthorizationServerMetadata<T>
	where
		T: Serialize,
	{
		fn into_response(self) -> Response {
			(&self).into_response()
		}
	}

	impl<T> IntoResponse for &AuthorizationServerMetadata<T>
	where
		T: Serialize,
	{
		fn into_response(self) -> ::axum::response::Response {
			Response::builder()
				.status(StatusCode::OK)
				.header(CONTENT_TYPE, &APPLICATION_JSON)
				.body(Body::from(
					serde_json::to_vec(self)
						// UNWRAP SAFETY: Authorization Server Metadata is
						//                always serializable as JSON.
						.unwrap(),
				))
				.unwrap()
		}
	}
}
