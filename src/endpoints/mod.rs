use iref::uri::QueryBuf;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{client::OAuth2ClientError, http::HttpClient, util::concat_query};

pub mod authorization;
pub mod pushed_authorization;
pub mod token;

#[derive(Serialize, Deserialize)]
pub struct NoExtension {}

pub trait Redirect {
	fn build_query(&self) -> QueryBuf;
}

pub trait Request {}

pub trait SendRequest<E>: Sized {
	type ResponsePayload;
	type Response;

	#[allow(async_fn_in_trait)]
	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<http::Request<Vec<u8>>, OAuth2ClientError>;

	fn parse_response(
		&self,
		endpoint: &E,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError>;

	#[allow(async_fn_in_trait)]
	async fn process_response(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, OAuth2ClientError>;

	#[allow(async_fn_in_trait)]
	async fn send(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<Self::Response, OAuth2ClientError> {
		let request = self.build_request(endpoint, http_client).await?;
		let response = http_client.send(request).await?;
		let parsed_response = self.parse_response(endpoint, response)?;
		self.process_response(endpoint, http_client, parsed_response)
			.await
	}
}

pub trait RequestBuilder {
	type Request;

	type Mapped<U>;

	fn map<U>(self, f: impl FnOnce(Self::Request) -> U) -> Self::Mapped<U>;
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stateful<T> {
	/// Opaque value used by the client to maintain state between the request
	/// and callback.
	///
	/// The authorization server includes this value when redirecting the
	/// user-agent back to the client. The parameter *should* be used for
	/// preventing cross-site request forgery.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
	pub state: Option<String>,

	#[serde(flatten)]
	pub value: T,
}

impl<T> Stateful<T> {
	pub fn new(value: T, state: Option<String>) -> Self {
		Self { state, value }
	}
}

impl<T> Request for Stateful<T> where T: Request {}

impl<T> Redirect for Stateful<T>
where
	T: Redirect,
{
	fn build_query(&self) -> QueryBuf {
		#[skip_serializing_none]
		#[derive(Serialize)]
		struct Params<'a> {
			state: Option<&'a str>,
		}

		concat_query(
			self.value.build_query(),
			Params {
				state: self.state.as_deref(),
			},
		)
	}
}

pub trait AddState {
	type Output;

	fn with_state(self, state: Option<String>) -> Self::Output;
}

impl<T> AddState for T
where
	T: RequestBuilder,
{
	type Output = T::Mapped<Stateful<T::Request>>;

	fn with_state(self, state: Option<String>) -> Self::Output {
		self.map(|value| Stateful::new(value, state))
	}
}
