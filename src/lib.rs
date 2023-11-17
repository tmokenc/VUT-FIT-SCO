#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod chacha20;
pub mod chacha20poly1305;
pub mod poly1305;

pub use chacha20::ChaCha20;
pub use chacha20::Key;
pub use chacha20::Nonce;

pub use poly1305::Key as Poly1305Key;
pub use poly1305::Poly1305;
pub use poly1305::Tag;

pub use chacha20poly1305::ChaCha20Poly1305;
