//! Rich Authorization Request.
//!
//! See: <https://www.rfc-editor.org/rfc/rfc9396.html>

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
	borrow::Borrow,
	ops::{Deref, DerefMut},
};

use crate::{
	endpoints::{HttpRequest, RedirectRequest, RequestBuilder},
	transport::HttpClient,
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

/// Collection of authorization detail objects.
///
/// When serialized as part of a form-encoded request, the objects are first
/// serialized as a JSON array string in the `authorization_details` field.
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

/// Extension wrapper that attaches authorization details to a request.
///
/// The authorization details are serialized alongside the inner request's
/// fields.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(bound = "D: AuthorizationDetailsObject, T: Serialize")]
pub struct WithAuthorizationDetails<'a, D, T> {
	/// The authorization detail objects to include.
	pub authorization_details: &'a [D],

	/// The inner request being extended.
	#[serde(flatten)]
	pub value: T,
}

impl<'a, D, T> WithAuthorizationDetails<'a, D, T> {
	/// Creates a new [`WithAuthorizationDetails`] wrapping the given request.
	pub fn new(value: T, authorization_details: &'a [D]) -> Self {
		Self {
			value,
			authorization_details,
		}
	}
}

impl<'a, D, T> Deref for WithAuthorizationDetails<'a, D, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

impl<'a, D, T> Borrow<T> for WithAuthorizationDetails<'a, D, T> {
	fn borrow(&self) -> &T {
		&self.value
	}
}

impl<'a, T, D, E> HttpRequest<E> for WithAuthorizationDetails<'a, D, T>
where
	T: HttpRequest<E>,
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
		http_client: &impl HttpClient,
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
		http_client: &impl crate::transport::HttpClient,
		response: http::Response<Self::ResponsePayload>,
	) -> Result<Self::Response, crate::client::OAuth2ClientError> {
		self.value
			.process_response(endpoint, http_client, response)
			.await
	}
}

impl<'a, T, D> RedirectRequest for WithAuthorizationDetails<'a, D, T>
where
	T: RedirectRequest,
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

/// Extension trait for attaching authorization details to a
/// [`RequestBuilder`].
pub trait AddAuthorizationDetails<'a, D> {
	/// The resulting type after adding authorization details.
	type Output;

	/// Wraps the current request with the given authorization details.
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
