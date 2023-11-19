#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub type Result<T> = core::result::Result<T, error::Error>;

pub mod chacha20;
pub mod chacha20poly1305;
pub mod error;
pub mod poly1305;

pub use chacha20::ChaCha20;
pub use chacha20::Key;
pub use chacha20::Nonce;

pub use poly1305::Key as Poly1305Key;
pub use poly1305::Poly1305;
pub use poly1305::Tag;

pub use chacha20poly1305::ChaCha20Poly1305;

use alloc::vec::Vec;

pub(crate) fn try_to_vec(data: &[u8]) -> Result<Vec<u8>> {
    let mut res = Vec::new();

    res.try_reserve(data.len())
        .map_err(|_| error::Error::OutOfMemory)?;
    res.copy_from_slice(data);

    Ok(res)
}
