use str_newtype::StrNewType;

/// A single OAuth 2.0 scope token (borrowed).
///
/// Scope tokens are the individual components of a [`Scope`] value, separated
/// by spaces.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
///
/// # Grammar
///
/// ```abnf
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(
	serde,
	owned(ScopeTokenBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash))
)]
pub struct ScopeToken(str);

impl ScopeToken {
	/// Validates that the given string is a well-formed scope token.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed scope token.
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

#[macro_export]
macro_rules! scope_token {
	($value:literal) => {{
		match $crate::ScopeToken::new($value) {
			Ok(value) => value,
			Err(_) => panic!("invalid scope token"),
		}
	}};
}

/// Conversion trait for types that can be turned into an optional [`ScopeBuf`].
pub trait IntoScope {
	/// Converts this value into an optional scope.
	///
	/// Returns `None` if the resulting scope would be empty.
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

/// An OAuth 2.0 scope value (borrowed).
///
/// A scope is a space-separated list of [`ScopeToken`]s representing the
/// permissions requested or granted for an access token.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
///
/// # Grammar
///
/// ```abnf
/// scope       = scope-token *( SP scope-token )
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, StrNewType)]
#[newtype(serde, owned(ScopeBuf, derive(PartialEq, Eq, PartialOrd, Ord, Hash)))]
pub struct Scope(str);

impl Scope {
	/// Validates that the given string is a well-formed scope.
	pub const fn validate_str(s: &str) -> bool {
		Self::validate_bytes(s.as_bytes())
	}

	/// Validates that the given byte slice is a well-formed scope.
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

	/// Returns `true` if this scope contains the given token.
	pub fn contains(&self, token: &ScopeToken) -> bool {
		self.iter().any(|t| t == token)
	}

	/// Returns an iterator over the individual scope tokens.
	pub fn iter(&self) -> ScopeIter<'_> {
		ScopeIter(self.0.split(' '))
	}
}

impl<'a> IntoIterator for &'a Scope {
	type IntoIter = ScopeIter<'a>;
	type Item = &'a ScopeToken;

	fn into_iter(self) -> Self::IntoIter {
		self.iter()
	}
}

#[macro_export]
macro_rules! scope {
	($value:literal) => {{
		match $crate::Scope::new($value) {
			Ok(value) => value,
			Err(_) => panic!("invalid scope"),
		}
	}};
}

/// Iterator over the individual [`ScopeToken`]s in a [`Scope`].
pub struct ScopeIter<'a>(std::str::Split<'a, char>);

impl<'a> Iterator for ScopeIter<'a> {
	type Item = &'a ScopeToken;

	fn next(&mut self) -> Option<Self::Item> {
		self.0
			.next()
			.map(|t| unsafe { ScopeToken::new_unchecked(t) })
	}
}

impl ScopeBuf {
	/// Builds a scope from an iterator of scope tokens.
	///
	/// Returns `None` if the iterator yields no tokens.
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

	/// Inserts a scope token if it is not already present.
	///
	/// Returns `true` if the token was inserted, `false` if it was already
	/// contained.
	pub fn insert(&mut self, token: &ScopeToken) -> bool {
		if self.contains(token) {
			false
		} else {
			self.0.push(' ');
			self.0.push_str(token.as_str());
			true
		}
	}
}

impl<'a> Extend<&'a ScopeToken> for ScopeBuf {
	fn extend<T: IntoIterator<Item = &'a ScopeToken>>(&mut self, iter: T) {
		for t in iter {
			self.insert(t);
		}
	}
}

impl<'a> IntoIterator for &'a ScopeBuf {
	type IntoIter = ScopeIter<'a>;
	type Item = &'a ScopeToken;

	fn into_iter(self) -> Self::IntoIter {
		self.iter()
	}
}
