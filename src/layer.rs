/// Creates a type and trait to extend OAuth2 types.
///
/// # Example
///
/// ```ignore
/// oauth2_extension! {
///   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
///   pub struct WithPkceCodeChallenge {
///     #[serde(flatten)]
///     pub pkce: PkceCodeChallengeAndMethod,
///
///     #[serde(flatten)]
///   }
///
///   pub trait PkceAuthorizationRequest { with_pkce }
/// }
/// ```
#[macro_export]
macro_rules! oauth2_extension {
	{
	    $(#[$ty_meta:meta])*
	    $ty_vis:vis struct $outer:ident $(<$($param:tt $(: $param_bound:tt)?),*>)? { $(#[$field_meta:meta])* pub $field:ident : $inner:ty $(, $(#[$value_meta:meta])*)? }
	} => {
	    $(#[$ty_meta])*
		$ty_vis struct $outer<$($($param,)*)? T> {
		    $(#[$field_meta])*
			pub $field: $inner,

			$($(#[$value_meta])*)?
			pub value: T,
		}

		impl<$($($param,)*)? T> $outer<$($($param,)*)? T> {
			pub fn new(value: T, $field: $inner) -> Self {
				Self { value, $field }
			}
		}

		impl<$($($param,)*)? T> std::ops::Deref for $outer<$($($param,)*)? T> {
			type Target = T;

			fn deref(&self) -> &Self::Target {
				&self.value
			}
		}

		impl<$($($param,)*)? T> std::borrow::Borrow<T> for $outer<$($($param,)*)? T> {
			fn borrow(&self) -> &T {
				&self.value
			}
		}
	};
}
