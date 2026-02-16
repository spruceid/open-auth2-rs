use std::{borrow::Cow, future::Future, sync::Arc};

use axum::{
	Form,
	body::Body,
	extract::{Query, State},
	http::{StatusCode, header::CONTENT_TYPE},
	response::{IntoResponse, Response},
	routing::{get, post},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
	Stateful, endpoints::pushed_authorization::PushedAuthorizationResponse, server::ErrorResponse,
	transport::APPLICATION_JSON,
};

use super::AuthorizationServerMetadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
	InvalidRequest,
	InvalidClient,
	InvalidGrant,
	UnauthorizedClient,
	UnsupportedGrantType,
	InvalidScope,
}

pub enum OAuth2ServerError {
	InvalidRequest,
	InvalidClient,
	InvalidGrant,
	UnauthorizedClient,
	UnsupportedGrantType,
	InvalidScope,
}

impl OAuth2ServerError {
	pub fn as_error_code(&self) -> Option<ErrorCode> {
		match self {
			Self::InvalidRequest => Some(ErrorCode::InvalidRequest),
			Self::InvalidClient => Some(ErrorCode::InvalidClient),
			Self::InvalidGrant => Some(ErrorCode::InvalidGrant),
			Self::UnauthorizedClient => Some(ErrorCode::UnauthorizedClient),
			Self::UnsupportedGrantType => Some(ErrorCode::UnsupportedGrantType),
			Self::InvalidScope => Some(ErrorCode::InvalidScope),
		}
	}
}

impl IntoResponse for OAuth2ServerError {
	fn into_response(self) -> Response {
		let error = match self.as_error_code() {
			Some(code) => code,
			None => {
				return Response::builder()
					.status(StatusCode::INTERNAL_SERVER_ERROR)
					.body(Body::empty())
					.unwrap();
			}
		};

		Response::builder()
			.status(StatusCode::BAD_REQUEST)
			.header(CONTENT_TYPE, &APPLICATION_JSON)
			.body(Body::from(
				serde_json::to_vec(&ErrorResponse::new(error, None, None)).unwrap(),
			))
			.unwrap()
	}
}

pub trait OAuth2Server: Sized + Send + Sync + 'static {
	type Metadata: Clone + Serialize;
	type AuthorizationRequest: Send + DeserializeOwned;
	type TokenRequest: Send + DeserializeOwned;
	type TokenResponse: Serialize;

	fn metadata(
		&self,
	) -> impl Send
	+ Future<
		Output = Result<Cow<'_, AuthorizationServerMetadata<Self::Metadata>>, OAuth2ServerError>,
	>;

	fn authorize(
		&self,
		request: Stateful<Self::AuthorizationRequest>,
	) -> impl Send + Future<Output = impl IntoResponse>;

	fn token(
		&self,
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
			get(metadata::<S>),
		)
		.route("/authorize", get(authorize::<S>))
		.route("/token", post(token::<S>))
	}
}

/// Credential Issuer Metadata Endpoint.
async fn metadata<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
	S: OAuth2Server,
{
	// TODO support `Accept-Language` header.
	server
		.metadata()
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
	Form(token_request): Form<S::TokenRequest>,
) -> impl IntoResponse
where
	S: OAuth2Server,
{
	server.token(token_request).await.map(|response| {
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
