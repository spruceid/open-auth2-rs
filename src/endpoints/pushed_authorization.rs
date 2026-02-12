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
		Redirect, Request, RequestBuilder, SendRequest,
		authorization::{AuthorizationEndpoint, AuthorizationEndpointLike},
	},
	http::{APPLICATION_JSON, HttpClient, WwwFormUrlEncoded, expect_content_type},
};

pub struct PushedAuthorizationEndpoint<'a, C> {
	pub client: &'a C,
	pub uri: &'a Uri,
}

impl<'a, C> PushedAuthorizationEndpoint<'a, C> {
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

impl<'a, C: OAuth2Client> AuthorizationEndpointLike for PushedAuthorizationEndpoint<'a, C> {
	type Client = C;
	type RequestBuilder<T> = PushedAuthorizationRequestBuilder<'a, C, T>;

	fn client(&self) -> &Self::Client {
		self.client
	}

	fn build_request<T>(self, request: T) -> Self::RequestBuilder<T> {
		PushedAuthorizationRequestBuilder::new(self, request)
	}
}

pub struct PushedAuthorizationRequestBuilder<'a, C, T> {
	endpoint: PushedAuthorizationEndpoint<'a, C>,
	request: T,
}

impl<'a, C, T> PushedAuthorizationRequestBuilder<'a, C, T> {
	pub fn new(endpoint: PushedAuthorizationEndpoint<'a, C>, value: T) -> Self {
		Self {
			endpoint,
			request: value,
		}
	}

	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> PushedAuthorizationRequestBuilder<'a, C, U> {
		PushedAuthorizationRequestBuilder {
			endpoint: self.endpoint,
			request: f(self.request),
		}
	}

	pub fn build(self) -> Pushed<T> {
		Pushed(self.request)
	}
}

impl<'a, C, T> PushedAuthorizationRequestBuilder<'a, C, T>
where
	T: Request + Redirect,
{
	pub async fn send(
		self,
		http_client: &impl HttpClient,
	) -> Result<PushedAuthorizationResponse, OAuth2ClientError> {
		let endpoint = self.endpoint;
		self.build().send(&endpoint, http_client).await
	}
}

impl<'a, C, T> RequestBuilder for PushedAuthorizationRequestBuilder<'a, C, T> {
	type Request = T;
	type Mapped<U> = PushedAuthorizationRequestBuilder<'a, C, U>;

	fn map<U>(self, f: impl FnOnce(Self::Request) -> U) -> Self::Mapped<U> {
		self.map(f)
	}
}

/// Pushed Authorization Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pushed<T>(T);

impl<'a, C, T> SendRequest<PushedAuthorizationEndpoint<'a, C>> for Pushed<T>
where
	T: Request + Redirect,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
	pub request_uri: UriBuf,
	pub expires_in: u64,
}

impl PushedAuthorizationResponse {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest<E = BTreeMap<String, String>> {
	pub client_id: ClientIdBuf,
	pub request_uri: UriBuf,

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
