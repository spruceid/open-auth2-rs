use iref::UriBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ErrorResponse<T = String> {
	pub error: T,

	pub error_description: Option<String>,

	pub error_uri: Option<UriBuf>,
}
