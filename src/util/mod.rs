//! URI query string utilities.
use iref::{
	UriBuf,
	uri::{Query, QueryBuf},
};
use serde::{Deserialize, Serialize};

mod discoverable;

pub use discoverable::*;

/// Placeholder type for structs that carry no extension fields.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NoExtension {}

/// Extends the query parameters of a URI by serializing `value` as
/// `application/x-www-form-urlencoded` and appending the result.
///
/// Existing query parameters on the URI are preserved.
///
/// # Panics
///
/// Panics if `value` cannot be serialized as form-urlencoded data.
pub fn extend_uri_query<T: Serialize>(uri: &mut UriBuf, value: T) {
	let query = serialize_concat_query(
		uri.query().map(ToOwned::to_owned).unwrap_or_default(),
		value,
	);

	uri.set_query(Some(
		Query::new(&query)
			// UNWRAP SAFETY: We trust `serde_html_form` to serialize the URI
			//                query correctly.
			.unwrap(),
	));
}

/// Serializes `value` as form-urlencoded data and concatenates it with the
/// existing query string.
///
/// # Panics
///
/// Panics if `value` cannot be serialized as form-urlencoded data.
pub fn serialize_concat_query<T>(query: QueryBuf, value: T) -> QueryBuf
where
	T: Serialize,
{
	concat_query(
		query,
		&QueryBuf::new(serde_html_form::to_string(value).unwrap().into_bytes()).unwrap(),
	)
}

/// Concatenates two query strings with `&` as separator.
///
/// If either query is empty, the other is returned as-is without a
/// separator.
pub fn concat_query(query: QueryBuf, other: &Query) -> QueryBuf {
	let mut query = query.into_string();

	if !query.is_empty() && !other.is_empty() {
		query.push('&')
	}

	query.push_str(other.as_str());

	QueryBuf::new(query.into_bytes()).unwrap()
}
