//! Pre-Authorized Code Grant.
//!
//! See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters>
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
	ClientIdBuf,
	client::{OAuth2Client, OAuth2ClientError},
	endpoints::{
		Request, SendRequest,
		authorization::AuthorizationEndpointLike,
		token::{TokenEndpoint, TokenRequestBuilder, TokenResponse},
	},
	http::{self, WwwFormUrlEncoded, expect_content_type},
};

impl<'a, C> TokenEndpoint<'a, C>
where
	C: OAuth2Client,
{
	pub fn exchange_pre_authorized_code(
		self,
		pre_authorized_code: String,
		tx_code: Option<String>,
	) -> TokenRequestBuilder<'a, C, PreAuthorizedCodeTokenRequest> {
		TokenRequestBuilder::new(
			self,
			PreAuthorizedCodeTokenRequest::new(
				Some(self.client.client_id().to_owned()),
				pre_authorized_code,
				tx_code,
			),
		)
	}
}

pub trait ExchangePreAuthorizedCode: AuthorizationEndpointLike {
	fn exchange_pre_authorized_code(
		self,
		pre_authorized_code: String,
		tx_code: Option<String>,
	) -> Self::RequestBuilder<PreAuthorizedCodeTokenRequest>;
}

impl<T: AuthorizationEndpointLike> ExchangePreAuthorizedCode for T {
	fn exchange_pre_authorized_code(
		self,
		pre_authorized_code: String,
		tx_code: Option<String>,
	) -> Self::RequestBuilder<PreAuthorizedCodeTokenRequest> {
		let client_id = self.client().client_id().to_owned();
		self.build_request(PreAuthorizedCodeTokenRequest::new(
			Some(client_id),
			pre_authorized_code,
			tx_code,
		))
	}
}

/// Token Request with Pre-Authorized Code Grant.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request>
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(
	tag = "grant_type",
	rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)]
pub struct PreAuthorizedCodeTokenRequest {
	pub client_id: Option<ClientIdBuf>,

	#[serde(rename = "pre-authorized_code")]
	pub pre_authorized_code: String,

	pub tx_code: Option<String>,
}

impl PreAuthorizedCodeTokenRequest {
	pub fn new(
		client_id: Option<ClientIdBuf>,
		pre_authorized_code: String,
		tx_code: Option<String>,
	) -> Self {
		Self {
			client_id,
			pre_authorized_code,
			tx_code,
		}
	}

	pub fn anonymous(self) -> Self {
		Self {
			client_id: None,
			..self
		}
	}
}

impl Request for PreAuthorizedCodeTokenRequest {}

impl<'a, C> SendRequest<TokenEndpoint<'a, C>> for PreAuthorizedCodeTokenRequest
where
	C: OAuth2Client,
{
	type ContentType = WwwFormUrlEncoded;
	type RequestBody<'b>
		= &'b Self
	where
		Self: 'b;
	type Response = TokenResponse<String, C::TokenParams>;
	type ResponsePayload = TokenResponse<String, C::TokenParams>;

	async fn build_request(
		&self,
		endpoint: &TokenEndpoint<'a, C>,
		_http_client: &impl http::HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
		Ok(http::Request::builder()
			.method(http::Method::POST)
			.uri(endpoint.uri.as_str())
			.body(self)
			.unwrap())
	}

	fn decode_response(
		&self,
		_endpoint: &TokenEndpoint<'a, C>,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
		if response.status() != http::StatusCode::OK {
			return Err(OAuth2ClientError::server(response.status()));
		}

		expect_content_type(response.headers(), &http::APPLICATION_JSON)?;

		let body = serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;

		Ok(response.map(|_| body))
	}

	async fn process_response(
		&self,
		_endpoint: &TokenEndpoint<'a, C>,
		_http_client: &impl crate::http::HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, OAuth2ClientError> {
		Ok(response.into_body())
	}
}
