# Cryptorust Library

Cryptorust is a collection of cryptographic primitives implemented in Rust.

## Modules

- `chacha20`: Module containing the Chacha20 stream cipher implementation.
- `poly1305`: Module containing the Poly1305 authenticator implementation.
- `chacha20poly1305`: Module combining Chacha20 and Poly1305 for authenticated encryption (AEAD).

## Types

### Chacha20 Module

- `Chacha20`: Represents the Chacha20 cipher state.
- `Key`: A type representing the Chacha20 key. It is an array of bytes with a size of `KEY_SIZE / 8`.
- `Nonce`: A type representing the Chacha20 nonce. It is an array of bytes with a size of `NONCE_SIZE / 8`.

### Poly1305 Module

- `Poly1305`: Represents the Poly1305 authenticator state.
- `Poly1305Key`: A type representing the Poly1305 key. It is an array of bytes with a size of `KEY_SIZE / 8`.
- `Tag`: A type representing the Poly1305 authentication tag. It is an array of bytes with a size of `TAG_SIZE / 8`.

### Chacha20Poly1305 Module

- `Chacha20Poly1305`: Represents the Chacha20-Poly1305 AEAD cipher state.

## Usage

To use this library, add the following to your `Cargo.toml` file:

```toml
[dependencies]
cryptorust = "0.1.0"
```

Then, in your Rust code, import the necessary types and modules:

```rust
extern crate cryptorust;

use cryptorust::{Chacha20, Key as Chacha20Key, Nonce, Poly1305, Poly1305Key, Tag, Chacha20Poly1305};
```

## Examples

Below is a simple example demonstrating the usage of the Chacha20 module:

```rust
// Example demonstrating the usage of the Chacha20 module
fn main() {
    let key: Chacha20Key = [0; cryptorust::chacha20::KEY_SIZE / 8];
    let nonce: Nonce = [1; cryptorust::chacha20::NONCE_SIZE / 8];

    let mut chacha = Chacha20::new(&key, &nonce);
    let data = b"example data";

    let result = chacha.perform(data);
    match result {
        Ok(encrypted) => println!("Encrypted data: {:?}", encrypted),
        Err(err) => eprintln!("Error: {:?}", err),
    }
}
```
