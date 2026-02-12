mod access_token;
mod client_id;
mod code;
mod scope;
mod state;

pub use access_token::*;
pub use client_id::*;
pub use code::*;
pub use scope::*;
pub use state::*;

const fn is_vschar(c: u8) -> bool {
	c >= 0x20 && c <= 0x7e
}
