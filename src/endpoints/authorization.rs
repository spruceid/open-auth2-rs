//! OAuth 2.0 authorization endpoint.
//!
//! See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.1>

use iref::Uri;
use serde::{Deserialize, Serialize};

use crate::{client::OAuth2Client, endpoints::Endpoint};

/// The OAuth 2.0 authorization endpoint.
///
/// This endpoint is used to interact with the resource owner and obtain an
/// authorization grant, as defined in
/// [RFC 6749 Section 3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1).
pub struct AuthorizationEndpoint<'a, C> {
	/// The OAuth 2.0 client.
	pub client: &'a C,

	/// The authorization endpoint URI.
	pub uri: &'a Uri,
}

impl<'a, C> AuthorizationEndpoint<'a, C> {
	/// Creates a new authorization endpoint for the given client and URI.
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

impl<'a, C> Endpoint for AuthorizationEndpoint<'a, C>
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

/// Trait abstracting over different authorization endpoint types.
///
/// This enables code that is generic over both standard authorization
/// endpoints and pushed authorization endpoints.
pub trait AnyAuthorizationEndpoint: Endpoint {
	/// The request wrapper type for this endpoint.
	type Request<T>;

	/// Wraps a request for this specific authorization endpoint type.
	fn build_authorization_request<T>(request: T) -> Self::Request<T>;
}

impl<'a, C> AnyAuthorizationEndpoint for AuthorizationEndpoint<'a, C>
where
	C: OAuth2Client,
{
	type Request<T> = T;

	fn build_authorization_request<T>(request: T) -> Self::Request<T> {
		request
	}
}

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
