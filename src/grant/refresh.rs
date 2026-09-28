/// The `grant_type` value used to request a token via the Refresh Token
/// Grant.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6749#section-6>
pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "grant_type", rename = "refresh_token")]
pub struct RefreshTokenRequest {
	pub client_id: Option<String>,
	pub refresh_token: String,
}
