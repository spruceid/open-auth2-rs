use str_newtype::StrNewType;

use super::is_vschar;

/// Code.
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
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

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
