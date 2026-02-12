use iref::UriBuf;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ErrorResponse<T = String> {
	pub error: T,

	pub error_description: Option<String>,

	pub error_uri: Option<UriBuf>,
}

impl<T> ErrorResponse<T> {
	pub fn new(error: T, error_description: Option<String>, error_uri: Option<UriBuf>) -> Self {
		Self {
			error,
			error_description,
			error_uri,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerResult<T, E = String> {
	Ok(T),
	Err(ErrorResponse<E>),
}
