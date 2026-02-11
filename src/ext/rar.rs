//! Rich Authorization Request.
//!
//! See: <https://www.rfc-editor.org/rfc/rfc9396.html>

use iref::uri::QueryBuf;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
	endpoints::{Redirect, Request, RequestBuilder},
	oauth2_extension,
	util::concat_query,
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

oauth2_extension! {
	#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
	pub struct WithAuthorizationDetails<D: AuthorizationDetailsObject> {
		pub authorization_details: Vec<D>,
	}
}

impl<T, D> Request for WithAuthorizationDetails<D, T>
where
	T: Request,
	D: AuthorizationDetailsObject,
{
}

impl<T, D> Redirect for WithAuthorizationDetails<D, T>
where
	T: Redirect,
	D: AuthorizationDetailsObject,
{
	fn build_query(&self) -> QueryBuf {
		#[derive(Serialize)]
		struct Params<'a, D: AuthorizationDetailsObject> {
			#[serde(skip_serializing_if = "<[_]>::is_empty", with = "as_json")]
			authorization_details: &'a [D],
		}

		concat_query(
			self.value.build_query(),
			Params {
				authorization_details: &self.authorization_details,
			},
		)
	}
}

pub trait AddAuthorizationDetails<D> {
	type Output;

	fn with_authorization_details(self, authorization_details: Vec<D>) -> Self::Output;
}

impl<'a, D, T> AddAuthorizationDetails<D> for T
where
	T: RequestBuilder,
{
	type Output = T::Mapped<WithAuthorizationDetails<D, T::Request>>;

	fn with_authorization_details(self, authorization_details: Vec<D>) -> Self::Output {
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
