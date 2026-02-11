#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "grant_type", rename = "refresh_token")]
pub struct RefreshTokenRequest {
	pub client_id: Option<String>,
	pub refresh_token: Sting,
}
