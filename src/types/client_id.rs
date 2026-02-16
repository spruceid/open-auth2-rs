use str_newtype::StrNewType;

use super::is_vschar;

/// An OAuth 2.0 client identifier (borrowed).
///
/// Client identifiers are unique strings issued to registered clients by the
/// authorization server, as defined in
/// [RFC 6749 Section 2.2](https://datatracker.ietf.org/doc/html/rfc6749#section-2.2).
///
/// Note that unlike most other OAuth 2.0 string types, a client identifier
/// may be empty (`*VSCHAR` rather than `1*VSCHAR`).
///
/// # Grammar
///
/// ```abnf
/// client_id = *VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(ClientIdBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct ClientId(str);

impl ClientId {
	/// Validates that the given string is a well-formed client identifier.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed client identifier.
	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		let mut i = 0;

		while i < bytes.len() {
			if !is_vschar(bytes[i]) {
				return false;
			}

			i += 1
		}

		true
	}
}

#[macro_export]
macro_rules! client_id {
	($value:literal) => {{
		match $crate::ClientId::new($value) {
			Ok(value) => value,
			Err(_) => panic!("invalid client identifier"),
		}
	}};
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn valid_client_id() {
		assert!(ClientId::new("my-client").is_ok());
		assert!(ClientId::new("a").is_ok());
		assert!(ClientId::new("client 123").is_ok());
	}

	#[test]
	fn empty_client_id_is_valid() {
		// Grammar is `*VSCHAR`, so empty is allowed.
		assert!(ClientId::new("").is_ok());
	}

	#[test]
	fn client_id_rejects_control_chars() {
		assert!(ClientId::new("\x00").is_err());
		assert!(ClientId::new("\x1f").is_err());
		assert!(ClientId::new("abc\ndef").is_err());
		assert!(ClientId::new("abc\x7f").is_err());
	}

	#[test]
	fn valid_client_id_buf() {
		assert!(ClientIdBuf::new("my-client".to_owned()).is_ok());
		assert!(ClientIdBuf::new("".to_owned()).is_ok());
	}

	#[test]
	fn invalid_client_id_buf() {
		assert!(ClientIdBuf::new("\x00".to_owned()).is_err());
	}
}
