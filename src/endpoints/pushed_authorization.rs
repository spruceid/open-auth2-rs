//! [RFC 9126]: OAuth 2.0 Pushed Authorization Requests.
//!
//! [RFC 9126]: <https://www.rfc-editor.org/rfc/rfc9126.html>
use std::collections::BTreeMap;

use http::StatusCode;
use iref::{
	Uri, UriBuf,
	uri::{Query, QueryBuf},
};
use serde::{Deserialize, Serialize};

use crate::{
	ClientIdBuf,
	client::{OAuth2Client, OAuth2ClientError},
	endpoints::{
		Endpoint, HttpRequest, RedirectRequest,
		authorization::{AnyAuthorizationEndpoint, AuthorizationEndpoint},
	},
	transport::{APPLICATION_JSON, HttpClient, WwwFormUrlEncoded, expect_content_type},
};

/// The OAuth 2.0 Pushed Authorization Request (PAR) endpoint.
///
/// This endpoint allows clients to push the payload of an authorization
/// request directly to the authorization server, receiving a `request_uri`
/// in return that can be used at the authorization endpoint.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9126.html>
pub struct PushedAuthorizationEndpoint<'a, C> {
	/// The OAuth 2.0 client.
	pub client: &'a C,

	/// The PAR endpoint URI.
	pub uri: &'a Uri,
}

impl<'a, C> PushedAuthorizationEndpoint<'a, C> {
	/// Creates a new PAR endpoint for the given client and URI.
	pub fn new(client: &'a C, uri: &'a Uri) -> Self {
		Self { client, uri }
	}
}

impl<'a, C> Clone for PushedAuthorizationEndpoint<'a, C> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<'a, C> Copy for PushedAuthorizationEndpoint<'a, C> {}

impl<'a, C> Endpoint for PushedAuthorizationEndpoint<'a, C>
where
	C: OAuth2Client,
{
	type Client = C;

	fn client(&self) -> &Self::Client {
		self.client
	}

	fn uri(&self) -> &Uri {
		self.uri
	}
}

impl<'a, C> AnyAuthorizationEndpoint for PushedAuthorizationEndpoint<'a, C>
where
	C: OAuth2Client,
{
	type Request<T> = Pushed<T>;

	fn build_authorization_request<T>(request: T) -> Self::Request<T> {
		Pushed(request)
	}
}

/// Wrapper marking a request as a Pushed Authorization Request.
///
/// When sent to a [`PushedAuthorizationEndpoint`], the inner request's query
/// parameters are POSTed as `application/x-www-form-urlencoded` instead of
/// being appended to a redirect URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pushed<T>(T);

impl<'a, C, T> HttpRequest<PushedAuthorizationEndpoint<'a, C>> for Pushed<T>
where
	T: RedirectRequest,
{
	type ContentType = WwwFormUrlEncoded;
	type RequestBody<'b>
		= T::RequestBody<'b>
	where
		Self: 'b;
	type ResponsePayload = PushedAuthorizationResponse;
	type Response = PushedAuthorizationResponse;

	async fn build_request(
		&self,
		endpoint: &PushedAuthorizationEndpoint<'a, C>,
		_http_client: &impl HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
		Ok(http::Request::builder()
			.method(http::Method::POST)
			.uri(endpoint.uri.as_str())
			.body(self.0.build_query())
			.unwrap())
	}

	fn decode_response(
		&self,
		_endpoint: &PushedAuthorizationEndpoint<'a, C>,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
		if response.status() != StatusCode::CREATED {
			return Err(OAuth2ClientError::server(response.status()));
		}

		expect_content_type(response.headers(), &APPLICATION_JSON)?;

		let body = serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;

		Ok(response.map(|_| body))
	}

	async fn process_response(
		&self,
		_endpoint: &PushedAuthorizationEndpoint<'a, C>,
		_http_client: &impl HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, OAuth2ClientError> {
		Ok(response.into_body())
	}
}

/// Successful response from the PAR endpoint.
///
/// Contains an opaque `request_uri` that the client uses at the
/// authorization endpoint, along with an expiration time.
#[derive(Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
	/// Opaque URI referencing the pushed authorization request.
	pub request_uri: UriBuf,

	/// Lifetime in seconds of the `request_uri`.
	pub expires_in: u64,
}

impl PushedAuthorizationResponse {
	/// Builds the authorization URI for the given authorization endpoint.
	///
	/// The returned URI contains the `client_id` and `request_uri` as query
	/// parameters, ready to redirect the user-agent to.
	pub fn for_endpoint<'a, C>(&self, endpoint: &AuthorizationEndpoint<'a, C>) -> UriBuf
	where
		C: OAuth2Client,
	{
		let mut uri = endpoint.uri.to_owned();

		let query = QueryBuf::new(
			serde_html_form::to_string(PushedAuthorizationRequest {
				client_id: endpoint.client.client_id().to_owned(),
				request_uri: self.request_uri.clone(),
				ext: serde_html_form::from_str::<BTreeMap<String, String>>(
					uri.query().map(Query::as_str).unwrap_or_default(),
				)
				.unwrap(),
			})
			.unwrap()
			.into_bytes(),
		)
		.unwrap();

		if !query.is_empty() {
			uri.set_query(Some(&query));
		}

		uri
	}
}

/// Authorization request referencing a previously pushed request.
///
/// This is the query sent to the authorization endpoint after a successful
/// PAR exchange, containing the `client_id` and the opaque `request_uri`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest<E = BTreeMap<String, String>> {
	/// The client identifier.
	pub client_id: ClientIdBuf,

	/// The opaque URI returned by the PAR endpoint.
	pub request_uri: UriBuf,

	/// Additional extension parameters.
	#[serde(flatten)]
	pub ext: E,
}

#[cfg(feature = "axum")]
mod axum {
	use ::axum::{
		body::Body,
		http::header,
		response::{IntoResponse, Response},
	};

	use super::*;

	impl IntoResponse for PushedAuthorizationResponse {
		fn into_response(self) -> Response {
			Response::builder()
				.status(StatusCode::CREATED)
				.header(header::CONTENT_TYPE, APPLICATION_JSON)
				.body(Body::from(serde_json::to_vec(&self).unwrap()))
				.unwrap()
		}
	}
}
