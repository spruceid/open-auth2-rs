//! Rich Authorization Request.
//!
//! See: <https://www.rfc-editor.org/rfc/rfc9396.html>

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::ops::{Deref, DerefMut};

use crate::{
	endpoints::{Redirect, RequestBuilder, SendRequest},
	oauth2_extension,
};

/// Authorization Details Object.
///
/// # Serialization
///
/// Implementors *must* be serializable as JSON.
pub trait AuthorizationDetailsObject: Serialize + DeserializeOwned {
	/// Identifier of the authorization detail type.
	fn r#type(&self) -> &str;
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(bound = "D: AuthorizationDetailsObject")]
pub struct AuthorizationDetails<D> {
	#[serde(
		rename = "authorization_details",
		with = "as_json",
		skip_serializing_if = "Vec::is_empty"
	)]
	objects: Vec<D>,
}

impl<D> From<Vec<D>> for AuthorizationDetails<D> {
	fn from(value: Vec<D>) -> Self {
		Self { objects: value }
	}
}

impl<D> Deref for AuthorizationDetails<D> {
	type Target = Vec<D>;

	fn deref(&self) -> &Self::Target {
		&self.objects
	}
}

impl<D> DerefMut for AuthorizationDetails<D> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.objects
	}
}

oauth2_extension! {
	#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
	pub struct WithAuthorizationDetails<'a, D: AuthorizationDetailsObject> {
		pub authorization_details: &'a [D]

		=> #[serde(flatten)]
	}
}

impl<'a, T, D, E> SendRequest<E> for WithAuthorizationDetails<'a, D, T>
where
	T: SendRequest<E>,
	D: AuthorizationDetailsObject,
{
	type ContentType = T::ContentType;
	type RequestBody<'b>
		= WithAuthorizationDetails<'a, D, T::RequestBody<'b>>
	where
		Self: 'b;
	type Response = T::Response;
	type ResponsePayload = T::ResponsePayload;

	async fn build_request(
		&self,
		endpoint: &E,
		http_client: &impl crate::http::HttpClient,
	) -> Result<http::Request<Self::RequestBody<'_>>, crate::client::OAuth2ClientError> {
		self.value
			.build_request(endpoint, http_client)
			.await
			.map(|request| {
				request
					.map(|value| WithAuthorizationDetails::new(value, self.authorization_details))
			})
	}

	fn decode_response(
		&self,
		endpoint: &E,
		response: http::Response<Vec<u8>>,
	) -> Result<http::Response<Self::ResponsePayload>, crate::client::OAuth2ClientError> {
		self.value.decode_response(endpoint, response)
	}

	async fn process_response(
		&self,
		endpoint: &E,
		http_client: &impl crate::http::HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, crate::client::OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

impl<'a, T, D> Redirect for WithAuthorizationDetails<'a, D, T>
where
	T: Redirect,
	D: AuthorizationDetailsObject,
{
	type RequestBody<'b>
		= WithAuthorizationDetails<'a, D, T::RequestBody<'b>>
	where
		Self: 'b;

	fn build_query(&self) -> Self::RequestBody<'_> {
		WithAuthorizationDetails::new(self.value.build_query(), self.authorization_details)
	}
}

pub trait AddAuthorizationDetails<'a, D> {
	type Output;

	fn with_authorization_details(self, authorization_details: &'a [D]) -> Self::Output;
}

impl<'a, D, E, T> AddAuthorizationDetails<'a, D> for RequestBuilder<E, T>
where
	D: 'a,
{
	type Output = RequestBuilder<E, WithAuthorizationDetails<'a, D, T>>;

	fn with_authorization_details(self, authorization_details: &'a [D]) -> Self::Output {
		self.map(|value| WithAuthorizationDetails::new(value, authorization_details))
	}
}

mod as_json {
	use serde::Deserialize;

	use crate::ext::rar::AuthorizationDetailsObject;

	pub fn serialize<T, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
		T: AuthorizationDetailsObject,
	{
		serializer.serialize_str(
			&serde_json::to_string(value)
				// UNWRAP SAFETY: The `T: AuthorizationDetailsObject` bound
				//                implies `T` can be serialized as JSON.
				.unwrap(),
		)
	}

	pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
	where
		D: serde::Deserializer<'de>,
		T: AuthorizationDetailsObject,
	{
		let string = String::deserialize(deserializer)?;
		serde_json::from_str(&string).map_err(serde::de::Error::custom)
	}
}
