use str_newtype::StrNewType;

use super::is_vschar;

/// An OAuth 2.0 authorization code (borrowed).
///
/// Authorization codes are short-lived credentials returned by the
/// authorization endpoint and exchanged at the token endpoint, as defined in
/// [RFC 6749 Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2).
///
/// # Grammar
///
/// ```abnf
/// code = 1*VSCHAR
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(serde, owned(CodeBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash)))]
pub struct Code(str);

impl Code {
	/// Validates that the given string is a well-formed authorization code.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed authorization code.
	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		let mut i = 0;

		while i < bytes.len() {
			if !is_vschar(bytes[i]) {
				return false;
			}

			i += 1
		}

		i > 0
	}
}

#[macro_export]
macro_rules! code {
	($value:literal) => {{
		match $crate::Code::new($value) {
			Ok(value) => value,
			Err(_) => panic!("invalid code"),
		}
	}};
}
