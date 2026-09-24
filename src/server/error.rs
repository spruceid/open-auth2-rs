use std::{convert::Infallible, str::FromStr};

use iref::UriBuf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::skip_serializing_none;

/// An OAuth 2.0 error response.
///
/// This is the standard error format returned by the authorization server
/// when a request fails, as defined in
/// [RFC 6749 Section 5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ErrorResponse<T = ErrorCode> {
	/// A single error code string.
	pub error: T,

	/// Human-readable text providing additional information about the error.
	pub error_description: Option<String>,

	/// A URI identifying a human-readable web page with information about
	/// the error.
	pub error_uri: Option<UriBuf>,
}

impl<T> ErrorResponse<T> {
	/// Creates a new error response.
	pub fn new(error: T, error_description: Option<String>, error_uri: Option<UriBuf>) -> Self {
		Self {
			error,
			error_description,
			error_uri,
		}
	}
}

/// Result type that deserializes as either a success payload or an
/// [`ErrorResponse`].
///
/// Uses `#[serde(untagged)]` to transparently handle both cases from a
/// single JSON response body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerResult<T, E = ErrorCode> {
	/// The request succeeded.
	Ok(T),

	/// The server returned an error.
	Err(ErrorResponse<E>),
}

macro_rules! error_codes {
	(
		$(
			$(#[$meta:meta])*
			$variant:ident => $str:literal
		),* $(,)?
	) => {
		/// OAuth error code.
		///
		/// [RFC 6749 §5.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		/// [§4.1.2.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
		/// [IANA "OAuth Extensions Error" registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error
		#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
		pub enum ErrorCode {
			$(
				$(#[$meta])*
				$variant,
			)*

			/// Any other error code not covered by this enum's other variants.
			Other(String),
		}

		impl ErrorCode {
            /// Parses an error code from its name.
    		pub fn new(name: &str) -> Self {
    			match name {
    				$($str => Self::$variant,)*
    				other => Self::Other(other.to_owned()),
    			}
    		}

			/// Returns the name of this error code.
			pub fn name(&self) -> &str {
				match self {
					$(Self::$variant => $str,)*
					Self::Other(other) => other,
				}
			}

			/// Returns the name of this error code.
			///
			/// Alias for [`Self::name`].
			pub fn as_str(&self) -> &str {
			    self.name()
			}
		}

		impl FromStr for ErrorCode {
			type Err = Infallible;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				Ok(Self::new(s))
			}
		}

		impl Serialize for ErrorCode {
			fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
			where
				S: Serializer,
			{
				serializer.serialize_str(self.as_str())
			}
		}

		impl<'de> Deserialize<'de> for ErrorCode {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: Deserializer<'de>,
			{
				String::deserialize(deserializer).map(|s| Self::new(&s))
			}
		}
	};
}

error_codes! {
	/// The request is missing a required parameter, includes an unsupported
	/// parameter value (other than grant type), repeats a parameter, includes
	/// multiple credentials, utilizes more than one mechanism for
	/// authenticating the client, or is otherwise malformed.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidRequest => "invalid_request",

	/// Client authentication failed (e.g., unknown client, no client
	/// authentication included, or unsupported authentication method).
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidClient => "invalid_client",

	/// The provided authorization grant (e.g., authorization code, resource
	/// owner credentials) or refresh token is invalid, expired, revoked,
	/// does not match the redirection URI used in the authorization
	/// request, or was issued to another client.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidGrant => "invalid_grant",

	/// The authenticated client is not authorized to use this authorization
	/// grant type.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	UnauthorizedClient => "unauthorized_client",

	/// The resource owner or authorization server denied the request.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	AccessDenied => "access_denied",

	/// The authorization server does not support obtaining an authorization
	/// code or access token using this method.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	UnsupportedResponseType => "unsupported_response_type",

	/// The authorization grant type is not supported by the authorization
	/// server.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	UnsupportedGrantType => "unsupported_grant_type",

	/// The requested scope is invalid, unknown, malformed, or exceeds the
	/// scope granted by the resource owner.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-5.2>
	InvalidScope => "invalid_scope",

	/// The authorization server encountered an unexpected condition that
	/// prevented it from fulfilling the request.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	ServerError => "server_error",

	/// The authorization server is currently unable to handle the request
	/// due to a temporary overloading or maintenance of the server.
	///
	/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1>
	TemporarilyUnavailable => "temporarily_unavailable",

	/// The requested resource could not be found.
	///
	/// Not part of RFC 6749; registered in the IANA "OAuth Extensions Error"
	/// registry for OpenID Federation.
	///
	/// See: <https://openid.net/specs/openid-federation-1_0.html#section-8.9>
	NotFound => "not_found",
}

#[cfg(test)]
mod tests {
	use super::ErrorCode;

	#[test]
	fn error_code_round_trips() {
		assert_eq!(ErrorCode::InvalidRequest.as_str(), "invalid_request");
		assert_eq!(ErrorCode::new("not_found"), ErrorCode::NotFound);
		assert_eq!(
			ErrorCode::new("totally_unknown"),
			ErrorCode::Other("totally_unknown".to_owned())
		);

		let json = serde_json::to_string(&ErrorCode::ServerError).unwrap();
		assert_eq!(json, "\"server_error\"");

		let parsed: ErrorCode = serde_json::from_str("\"custom_thing\"").unwrap();
		assert_eq!(parsed, ErrorCode::Other("custom_thing".to_owned()));

		let via_trait: ErrorCode = "invalid_scope".parse().unwrap();
		assert_eq!(via_trait, ErrorCode::InvalidScope);
	}
}
