//! Core OAuth 2.0 types.
//!
//! This module defines the fundamental string types used throughout the OAuth
//! 2.0 protocol, each validated against the grammar specified in
//! [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).
//!
//! All types come in borrowed/owned pairs (e.g. [`AccessToken`] /
//! [`AccessTokenBuf`]) following the same pattern as [`str`] / [`String`].
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

/// Returns `true` if the byte is a VSCHAR (visible ASCII character plus
/// space), i.e. in the range `0x20..=0x7E`.
const fn is_vschar(c: u8) -> bool {
	c >= 0x20 && c <= 0x7e
}

/// Returns `true` if the byte is a NQCHAR.
const fn is_nqchar(c: u8) -> bool {
	c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
}
