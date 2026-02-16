//! OAuth 2.0 endpoint abstractions and request/response traits.
//!
//! This module provides the core traits for interacting with OAuth 2.0
//! endpoints:
//!
//! - [`Endpoint`] — associates a client with an endpoint.
//! - [`HttpRequest`] — builds, sends, and decodes HTTP requests.
//! - [`RedirectRequest`] — builds query parameters for redirect-based flows.
//! - [`RequestBuilder`] — fluent builder for composing requests with
//!   extensions.
use std::collections::BTreeMap;

use http::header::CONTENT_TYPE;
use iref::{
	Uri, UriBuf,
	uri::{Query, QueryBuf},
};
use serde::Serialize;

use crate::{
	client::{OAuth2Client, OAuth2ClientError},
	transport::{ContentType, HttpClient, WwwFormUrlEncoded},
};

pub mod authorization;
pub mod pushed_authorization;
pub mod token;

/// An OAuth 2.0 endpoint bound to a specific client.
pub trait Endpoint {
	/// The client type associated with this endpoint.
	type Client: OAuth2Client;

	/// Returns a reference to the associated client.
	fn client(&self) -> &Self::Client;

	fn uri(&self) -> &Uri;
}

/// A request that can be serialized into URI query parameters for a
/// redirect-based flow (e.g. the authorization endpoint).
pub trait RedirectRequest {
	/// The serializable body type produced by [`build_query`](Self::build_query).
	type RequestBody<'b>: Serialize
	where
		Self: 'b;

	/// Builds the query parameters for this redirect request.
	fn build_query(&self) -> Self::RequestBody<'_>;

	/// Converts this request builder into a complete redirect URI.
	///
	/// The request parameters are serialized as query parameters and appended
	/// to the authorization endpoint URI.
	fn redirect_uri<E>(&self, endpoint: &E) -> UriBuf
	where
		E: Endpoint,
	{
		let mut uri = endpoint.uri().to_owned();

		#[derive(Serialize)]
		struct WithAuthorizationRequest<T> {
			#[serde(flatten)]
			args: BTreeMap<String, String>,

			#[serde(flatten)]
			authorization_params: T,
		}

		let query = QueryBuf::new(WwwFormUrlEncoded::encode(&WithAuthorizationRequest {
			args: serde_html_form::from_str(uri.query().map(Query::as_str).unwrap_or_default())
				.unwrap(),
			authorization_params: self.build_query(),
		}))
		.unwrap();

		if !query.is_empty() {
			uri.set_query(Some(&query));
		}

		uri
	}
}

/// A request that can be sent to an endpoint over HTTP.
///
/// This trait handles the full lifecycle of an HTTP request: building the
/// request, decoding the raw response, and post-processing the decoded
/// payload into the final response type.
pub trait HttpRequest<E>: Sized {
	/// The content type used to encode the request body.
	type ContentType: ContentType;

	/// The serializable request body type.
	type RequestBody<'b>: Serialize
	where
		Self: 'b;

	/// The intermediate payload type obtained by decoding the raw HTTP
	/// response bytes.
	type ResponsePayload;

	/// The final response type returned after post-processing.
	type Response;

	/// Builds an HTTP request for this endpoint.
	#[allow(async_fn_in_trait)]
	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError>;

	/// Decodes a raw HTTP response into the intermediate payload type.
	fn decode_response(
		&self,
		endpoint: &E,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError>;

	/// Post-processes the decoded response into the final response type.
	///
	/// This step may perform additional HTTP exchanges (e.g. DPoP nonce
	/// retry).
	#[allow(async_fn_in_trait)]
	async fn process_response(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, OAuth2ClientError>;

	/// Convenience method that builds, sends, decodes, and processes a
	/// request in a single call.
	#[allow(async_fn_in_trait)]
	async fn send(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<Self::Response, OAuth2ClientError> {
		let mut request = self.build_request(endpoint, http_client).await?;
		if let Some(content_type) = Self::ContentType::VALUE {
			request.headers_mut().insert(CONTENT_TYPE, content_type);
		}
		let encoded_request = request.map(|body| Self::ContentType::encode(&body));
		let response = http_client.send(encoded_request).await?;
		let decoded_response = self.decode_response(endpoint, response)?;
		self.process_response(endpoint, http_client, decoded_response)
			.await
	}
}

/// Fluent builder for composing an endpoint request with extensions.
///
/// Extension traits (such as [`AddState`](crate::AddState),
/// [`AddPkceChallenge`](crate::ext::pkce::AddPkceChallenge), etc.) add
/// methods to `RequestBuilder` that wrap the inner request with additional
/// parameters.
pub struct RequestBuilder<E, T> {
	/// The endpoint this request targets.
	pub endpoint: E,

	/// The request being built.
	pub request: T,
}

impl<E, T> RequestBuilder<E, T> {
	/// Creates a new request builder for the given endpoint and request.
	pub fn new(endpoint: E, request: T) -> Self {
		Self { endpoint, request }
	}

	/// Transforms the inner request using the provided closure.
	///
	/// This is the mechanism used by extension traits to wrap the request
	/// in additional layers.
	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> RequestBuilder<E, U> {
		RequestBuilder::new(self.endpoint, f(self.request))
	}

	/// Sends the built request using the provided HTTP client.
	pub async fn send(self, http_client: &impl HttpClient) -> Result<T::Response, OAuth2ClientError>
	where
		T: HttpRequest<E>,
	{
		let endpoint = self.endpoint;
		self.request.send(&endpoint, http_client).await
	}

	/// Converts this request builder into a redirect URI.
	///
	/// The request parameters are serialized as query parameters and appended
	/// to the authorization endpoint URI.
	pub fn into_redirect_uri(self) -> UriBuf
	where
		E: Endpoint,
		T: RedirectRequest,
	{
		let endpoint = self.endpoint;
		self.request.redirect_uri(&endpoint)
	}
}
