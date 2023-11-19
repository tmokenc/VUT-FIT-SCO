# Chacha20Poly1305

This is my school project for the course Secure Coding

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
chacha20poly1305 = { git = "https://github.com/tmokenc/VUT-FIT-SCO" }
```

## Test

To comfirm the correctness of the library

```sh
cargo test --package chacha20poly1305
```

## Examples

Below is a simple example demonstrating the usage of the Chacha20 module:

```rust
use rand::prelude::*;
use chacha20poly1305::{Chacha20, Key, Nonce};

fn main() {
    let mut rng = thread_rng();
    let key: Key = rng.gen();
    let nonce: Nonce = rng.gen();

    let mut chacha = Chacha20::new(&key, &nonce);
    let data = b"example data";

    match  chacha.perform(data) {
        Ok(encrypted) => println!("Encrypted data: {:?}", encrypted),
        Err(err) => eprintln!("Error: {:?}", err),
    }
}
```
