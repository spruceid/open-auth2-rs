use iref::{
	UriBuf,
	uri::{Query, QueryBuf},
};
use serde::Serialize;

/// Extend the query parameters.
///
/// # Panic
///
/// Caller is responsible for ensuring the input `value` can be serialized as
/// `application/x-www-form-urlencoded`. This function will panic otherwise.
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

/// Concatenates the query with the serialized input `value`.
///
/// # Panic
///
/// Caller is responsible for ensuring the input `value` can be serialized as
/// `application/x-www-form-urlencoded`. This function will panic otherwise.
pub fn serialize_concat_query<T>(query: QueryBuf, value: T) -> QueryBuf
where
	T: Serialize,
{
	concat_query(
		query,
		&QueryBuf::new(serde_html_form::to_string(value).unwrap().into_bytes()).unwrap(),
	)
}

pub fn concat_query(query: QueryBuf, other: &Query) -> QueryBuf {
	let mut query = query.into_string();

	if !query.is_empty() && !other.is_empty() {
		query.push('&')
	}

	query.push_str(other.as_str());

	QueryBuf::new(query.into_bytes()).unwrap()
}
