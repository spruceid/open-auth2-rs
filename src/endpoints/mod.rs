use http::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use crate::{
	client::{OAuth2Client, OAuth2ClientError},
	http::{ContentType, HttpClient},
};

pub mod authorization;
pub mod pushed_authorization;
pub mod token;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NoExtension {}

pub trait Endpoint {
	type Client: OAuth2Client;

	fn client(&self) -> &Self::Client;
}

pub trait Redirect {
	type RequestBody<'b>: Serialize
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_>;
}

pub trait SendRequest<E>: Sized {
	type ContentType: ContentType;
	type RequestBody<'b>: Serialize
	where
		Self: 'b;
	type ResponsePayload;
	type Response;

	#[allow(async_fn_in_trait)]
	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError>;

	fn decode_response(
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

pub struct RequestBuilder<E, T> {
	pub endpoint: E,
	pub request: T,
}

impl<E, T> RequestBuilder<E, T> {
	pub fn new(endpoint: E, request: T) -> Self {
		Self { endpoint, request }
	}

	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> RequestBuilder<E, U> {
		RequestBuilder::new(self.endpoint, f(self.request))
	}

	pub async fn send(self, http_client: &impl HttpClient) -> Result<T::Response, OAuth2ClientError>
	where
		T: SendRequest<E>,
	{
		let endpoint = self.endpoint;
		self.request.send(&endpoint, http_client).await
	}
}
