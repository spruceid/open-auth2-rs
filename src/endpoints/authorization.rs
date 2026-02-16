use std::collections::BTreeMap;

use iref::{
	Uri, UriBuf,
	uri::{Query, QueryBuf},
};
use serde::{Deserialize, Serialize};

use crate::{
	client::OAuth2Client,
	endpoints::{Endpoint, Redirect, RequestBuilder},
	http::{ContentType, WwwFormUrlEncoded},
};

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

impl<'a, C> Endpoint for AuthorizationEndpoint<'a, C>
where
	C: OAuth2Client,
{
	type Client = C;

	fn client(&self) -> &Self::Client {
		self.client
	}
}

pub trait AnyAuthorizationEndpoint: Endpoint {
	type Request<T>;

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

// impl<'a, C: OAuth2Client> AuthorizationEndpointLike for AuthorizationEndpoint<'a, C> {
// 	type Client = C;
// 	type RequestBuilder<T> = AuthorizationRequestBuilder<'a, C, T>;

// 	fn client(&self) -> &Self::Client {
// 		self.client
// 	}

// 	fn build_request<T>(self, request: T) -> Self::RequestBuilder<T> {
// 		AuthorizationRequestBuilder::new(self, request)
// 	}
// }

impl<'a, C, T> RequestBuilder<AuthorizationEndpoint<'a, C>, T> {
	pub fn into_uri(self) -> UriBuf
	where
		T: Redirect,
	{
		let mut uri = self.endpoint.uri.to_owned();

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
			authorization_params: self.request.build_query(),
		}))
		.unwrap();

		if !query.is_empty() {
			uri.set_query(Some(&query));
		}

		uri
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
