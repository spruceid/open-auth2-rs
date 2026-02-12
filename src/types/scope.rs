use str_newtype::StrNewType;

/// Access Token Scope Token.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
///
/// # Grammar
///
/// ```
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(ScopeTokenBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct ScopeToken(str);

impl ScopeToken {
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		const fn is_scope_token_char(c: u8) -> bool {
			c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
		}

		let mut i = 0;

		while i < bytes.len() {
			if !is_scope_token_char(bytes[i]) {
				return false;
			}

			i += 1;
		}

		i > 1
	}
}

pub trait IntoScope {
	fn into_scope(self) -> Option<ScopeBuf>;
}

impl IntoScope for Option<ScopeBuf> {
	fn into_scope(self) -> Option<ScopeBuf> {
		self
	}
}

impl IntoScope for Vec<ScopeTokenBuf> {
	fn into_scope(self) -> Option<ScopeBuf> {
		ScopeBuf::from_tokens(self.iter().map(|t| t.as_scope_token()))
	}
}

impl IntoScope for &[ScopeTokenBuf] {
	fn into_scope(self) -> Option<ScopeBuf> {
		ScopeBuf::from_tokens(self.iter().map(|t| t.as_scope_token()))
	}
}

/// Access Token Scope.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
///
/// # Grammar
///
/// ```
/// scope       = scope-token *( SP scope-token )
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(serde, owned(ScopeBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash)))]
pub struct Scope(str);

impl Scope {
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	pub const fn validate_bytes(bytes: &[u8]) -> bool {
		const fn is_scope_token_char(c: u8) -> bool {
			c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
		}

		let mut i = 0;

		let mut expect_token = true;
		while expect_token {
			expect_token = false;
			let mut scope_token_empty = true;

			while i < bytes.len() {
				match bytes[i] {
					c if is_scope_token_char(c) => {
						scope_token_empty = false;
					}
					b' ' => {
						expect_token = true;
						break;
					}
					_ => return false,
				}

				i += 1;
			}

			if scope_token_empty {
				return false;
			}
		}

		true
	}
}

impl ScopeBuf {
	pub fn from_tokens<T>(tokens: impl IntoIterator<Item = T>) -> Option<Self>
	where
		T: AsRef<ScopeToken>,
	{
		let mut result = String::new();

		for token in tokens {
			if !result.is_empty() {
				result.push(' ');
			}

			result.push_str(token.as_ref().as_str());
		}

		if result.is_empty() {
			None
		} else {
			Some(Self(result))
		}
	}
}
