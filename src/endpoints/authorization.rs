use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};

use crate::{
	client::OAuth2Client,
	endpoints::{Redirect, RequestBuilder},
};

pub trait AuthorizationEndpointLike: Sized {
	type Client: OAuth2Client;
	type RequestBuilder<T>: RequestBuilder<Request = T>;

	fn client(&self) -> &Self::Client;

	fn build_request<T>(self, request: T) -> Self::RequestBuilder<T>;
}

pub struct AuthorizationEndpoint<'a, C> {
	pub client: &'a C,
	pub uri: &'a Uri,
}

impl<'a, C> AuthorizationEndpoint<'a, C> {
	pub fn new(client: &'a C, uri: &'a Uri) -> Self {
		Self { client, uri }
	}
}

impl<'a, C> Clone for AuthorizationEndpoint<'a, C> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<'a, C> Copy for AuthorizationEndpoint<'a, C> {}

impl<'a, C: OAuth2Client> AuthorizationEndpointLike for AuthorizationEndpoint<'a, C> {
	type Client = C;
	type RequestBuilder<T> = AuthorizationRequestBuilder<'a, C, T>;

	fn client(&self) -> &Self::Client {
		self.client
	}

	fn build_request<T>(self, request: T) -> Self::RequestBuilder<T> {
		AuthorizationRequestBuilder::new(self, request)
	}
}

pub struct AuthorizationRequestBuilder<'a, C, T> {
	pub endpoint: AuthorizationEndpoint<'a, C>,
	pub request: T,
}

impl<'a, C, T> AuthorizationRequestBuilder<'a, C, T> {
	pub fn new(endpoint: AuthorizationEndpoint<'a, C>, request: T) -> Self {
		Self { endpoint, request }
	}

	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> AuthorizationRequestBuilder<'a, C, U> {
		AuthorizationRequestBuilder {
			endpoint: self.endpoint,
			request: f(self.request),
		}
	}

	pub fn into_uri(self) -> UriBuf
	where
		T: Redirect,
	{
		let mut uri = self.endpoint.uri.to_owned();
		let query = uri.query().map(ToOwned::to_owned).unwrap_or_default();
		let more_query = self.request.build_query();
		todo!()
	}
}

impl<'a, C, T> RequestBuilder for AuthorizationRequestBuilder<'a, C, T> {
	type Request = T;
	type Mapped<U> = AuthorizationRequestBuilder<'a, C, U>;

	fn map<U>(self, f: impl FnOnce(Self::Request) -> U) -> Self::Mapped<U> {
		self.map(f)
	}
}

// pub trait AuthorizationRequest: Serialize {
// 	fn redirect_url(&self, endpoint_uri: &Uri) -> UriBuf {
// 		let mut url = endpoint_uri.to_owned();
// 		extend_uri_query(&mut url, self);
// 		url
// 	}
// }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorCode {
	/// The request is missing a required parameter, includes an invalid parameter value,
	/// includes a parameter more than once, or is otherwise malformed.
	InvalidRequest,

	/// The client is not authorized to request an authorization code using this method.
	UnauthorizedClient,

	/// The resource owner or authorization server denied the request.
	AccessDenied,

	/// The authorization server does not support obtaining an authorization code using this method.
	UnsupportedResponseType,

	/// The requested scope is invalid, unknown, or malformed.
	InvalidScope,

	/// The authorization server encountered an unexpected condition that prevented it from
	/// fulfilling the request. (This error code is needed because a 500 Internal Server
	/// Error HTTP status code cannot be returned to the client via an HTTP redirect.)
	ServerError,

	/// The authorization server is currently unable to handle the request due to a temporary
	/// overloading or maintenance of the server. (This error code is needed because a 503
	/// Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
	TemporarilyUnavailable,
}
