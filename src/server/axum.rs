use std::{borrow::Cow, future::Future, sync::Arc};

use axum::{
	Form,
	body::Body,
	extract::{Path as PathParam, Query, State},
	http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
	response::{IntoResponse, Response},
	routing::{get, post},
};
use iref::uri::Path;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
	Stateful, endpoints::pushed_authorization::PushedAuthorizationResponse, server::ErrorResponse,
	transport::APPLICATION_JSON,
};

use super::{AuthorizationServerMetadata, ErrorCode};

/// OAuth2 server error.
pub enum OAuth2ServerError {
	/// The requested resource could not be found.
	///
	/// See: <https://openid.net/specs/openid-federation-1_0.html#section-8.9>
	NotFound,

	/// The request is malformed.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidRequest,

	/// Client authentication failed.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidClient,

	/// The authorization grant or refresh token is invalid.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidGrant,

	/// The client is not authorized to use this grant type.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	UnauthorizedClient,

	/// The resource owner or authorization server denied the request.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	AccessDenied,

	/// The authorization server does not support this response type.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	UnsupportedResponseType,

	/// The authorization grant type is not supported.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	UnsupportedGrantType,

	/// The requested scope is invalid, unknown, or malformed.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidScope,

	/// The server is temporarily overloaded or under maintenance.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	TemporarilyUnavailable,

	/// Internal server error.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	Internal(String),
}

impl OAuth2ServerError {
	pub fn internal(e: impl ToString) -> Self {
		Self::Internal(e.to_string())
	}

	pub fn as_error_code(&self) -> ErrorCode {
		match self {
			Self::NotFound => ErrorCode::NotFound,
			Self::InvalidRequest => ErrorCode::InvalidRequest,
			Self::InvalidClient => ErrorCode::InvalidClient,
			Self::InvalidGrant => ErrorCode::InvalidGrant,
			Self::UnauthorizedClient => ErrorCode::UnauthorizedClient,
			Self::AccessDenied => ErrorCode::AccessDenied,
			Self::UnsupportedResponseType => ErrorCode::UnsupportedResponseType,
			Self::UnsupportedGrantType => ErrorCode::UnsupportedGrantType,
			Self::InvalidScope => ErrorCode::InvalidScope,
			Self::TemporarilyUnavailable => ErrorCode::TemporarilyUnavailable,
			Self::Internal(_) => ErrorCode::ServerError,
		}
	}

	pub fn status_code(&self) -> StatusCode {
		match self {
			Self::NotFound => StatusCode::NOT_FOUND,
			Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
			Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
			_ => StatusCode::BAD_REQUEST,
		}
	}

	pub fn description(&self) -> Option<&str> {
		match self {
			Self::Internal(e) => Some(e),
			_ => None,
		}
	}
}

impl IntoResponse for OAuth2ServerError {
	fn into_response(self) -> Response {
		Response::builder()
			.status(self.status_code())
			.header(CONTENT_TYPE, &APPLICATION_JSON)
			.body(Body::from(
				serde_json::to_vec(&ErrorResponse::new(
					self.as_error_code(),
					self.description().map(ToOwned::to_owned),
					None,
				))
				.unwrap(),
			))
			.unwrap()
	}
}

pub trait OAuth2Server: Sized + Send + Sync + 'static {
	type Metadata: Clone + Serialize;
	type AuthorizationRequest: Send + DeserializeOwned;
	type TokenRequest: Send + DeserializeOwned;
	type TokenResponse: Serialize;

	/// Returns the authorization server metadata for the given tenant path.
	///
	/// The `path` argument is the suffix of the well-known metadata URL after
	/// `/.well-known/oauth-authorization-server`, and identifies the tenant
	/// issuer as defined in [RFC 8414 §3]:
	///
	/// | Request path | `path` argument | Issuer |
	/// |---|---|---|
	/// | `/.well-known/oauth-authorization-server` | `None` | `https://example.com` |
	/// | `/.well-known/oauth-authorization-server/` | `Some("")` | `https://example.com/` |
	/// | `/.well-known/oauth-authorization-server/tenant` | `Some("tenant")` | `https://example.com/tenant` |
	/// | `/.well-known/oauth-authorization-server/foo/bar` | `Some("foo/bar")` | `https://example.com/foo/bar` |
	///
	/// [RFC 8414 §3]: https://datatracker.ietf.org/doc/html/rfc8414#section-3
	fn metadata(
		&self,
		path: Option<&Path>,
	) -> impl Send
	+ Future<
		Output = Result<Cow<'_, AuthorizationServerMetadata<Self::Metadata>>, OAuth2ServerError>,
	>;

	fn authorize(
		&self,
		request: Stateful<Self::AuthorizationRequest>,
	) -> impl Send + Future<Output = impl IntoResponse>;

	/// Token endpoint.
	///
	/// The request `headers` are provided because the token endpoint may need to
	/// process HTTP headers carrying client/key-binding material, such as the
	/// `DPoP` header (RFC 9449) or `OAuth-Client-Attestation`(-PoP) headers
	/// (Attestation-Based Client Authentication).
	fn token(
		&self,
		headers: HeaderMap,
		token_request: Self::TokenRequest,
	) -> impl Send + Future<Output = Result<Self::TokenResponse, OAuth2ServerError>>;
}

pub trait OAuth2Router<S> {
	fn oauth2_routes(self) -> Self;
}

impl<S: OAuth2Server> OAuth2Router<S> for axum::Router<Arc<S>> {
	fn oauth2_routes(self) -> Self {
		self.route(
			"/.well-known/oauth-authorization-server",
			get(metadata_none::<S>),
		)
		.route(
			"/.well-known/oauth-authorization-server/",
			get(metadata_some_empty::<S>),
		)
		.route(
			"/.well-known/oauth-authorization-server/{*tenant}",
			get(metadata_some_non_empty::<S>),
		)
		.route("/authorize", get(authorize::<S>))
		.route("/token", post(token::<S>))
	}
}

async fn metadata_none<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
	S: OAuth2Server,
{
	// TODO support `Accept-Language` header.
	server
		.metadata(None)
		.await
		.map(|metadata| metadata.as_ref().into_response())
}

async fn metadata_some_empty<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
	S: OAuth2Server,
{
	// TODO support `Accept-Language` header.
	server
		.metadata(Some(Path::EMPTY_RELATIVE))
		.await
		.map(|metadata| metadata.as_ref().into_response())
}

async fn metadata_some_non_empty<S>(
	State(server): State<Arc<S>>,
	PathParam(tenant): PathParam<String>,
) -> impl IntoResponse
where
	S: OAuth2Server,
{
	// TODO support `Accept-Language` header.
	let path = Path::new(&tenant)
		// UNWRAP SAFETY: axum wildcard paths are always valid iref paths.
		.unwrap();
	server
		.metadata(Some(path))
		.await
		.map(|metadata| metadata.as_ref().into_response())
}

/// Authorization Request endpoint.
async fn authorize<S>(
	State(server): State<Arc<S>>,
	Query(request): Query<Stateful<S::AuthorizationRequest>>,
) -> Response
where
	S: OAuth2Server,
{
	server.authorize(request).await.into_response()
}

/// Token Request endpoint.
async fn token<S>(
	State(server): State<Arc<S>>,
	headers: HeaderMap,
	Form(token_request): Form<S::TokenRequest>,
) -> impl IntoResponse
where
	S: OAuth2Server,
{
	server.token(headers, token_request).await.map(|response| {
		Response::builder()
			.status(StatusCode::OK)
			.header(CONTENT_TYPE, &APPLICATION_JSON)
			.body(Body::from(serde_json::to_vec(&response).unwrap()))
			.unwrap()
	})
}

pub trait OAuth2ParServer: OAuth2Server {
	type PushedAuthorizationRequest: Send + DeserializeOwned;

	fn par(
		&self,
		request: Stateful<Self::PushedAuthorizationRequest>,
	) -> impl Send + Future<Output = Result<PushedAuthorizationResponse, OAuth2ServerError>>;
}

pub trait OAuth2ParRouter<S> {
	fn oauth2_par_route(self) -> Self;
}

impl<S: OAuth2ParServer> OAuth2ParRouter<S> for axum::Router<Arc<S>> {
	fn oauth2_par_route(self) -> Self {
		self.route("/par", post(par::<S>))
	}
}

async fn par<S>(
	State(server): State<Arc<S>>,
	Form(request): Form<Stateful<S::PushedAuthorizationRequest>>,
) -> impl IntoResponse
where
	S: OAuth2ParServer,
{
	server.par(request).await
}
