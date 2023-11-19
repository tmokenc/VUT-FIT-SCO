//! Implementation of the Poly1305 cryptographic primitive for authenticating messages.

mod cross_arch;

use core::hint::black_box;
use cross_arch::Poly1305Inner;
use zeroize::Zeroize;

const KEY_SIZE: usize = 256;
const TAG_SIZE: usize = 128;
const BLOCK_SIZE: usize = 16;

/// Represents the Poly1305 key. It is an array of bytes with a size of 32, or 256 bits
pub type Key = [u8; KEY_SIZE / 8];
/// Represents the Poly1305 authentication tag. It is an array of bytes with a size of 16, or 128
/// bits
pub type Tag = [u8; TAG_SIZE / 8];

type Block = [u8; BLOCK_SIZE];

#[derive(Clone)]
/// Represents the Poly1305 state.
pub struct Poly1305 {
    inner: Poly1305Inner,
    buffer: Block,
    leftover: usize,
}

impl Poly1305 {
    /// Creates a new Poly1305 instance with the provided key.
    pub fn new(key: &Key) -> Self {
        Self {
            inner: Poly1305Inner::new(key),
            buffer: Default::default(),
            leftover: 0,
        }
    }

    /// Updates the Poly1305 state with the given data.
    pub fn update(&mut self, data: &[u8]) {
        let mut start_idx = 0;

        if self.leftover != 0 {
            let mut leftover_fill_size = BLOCK_SIZE - self.leftover;

            if leftover_fill_size > data.len() {
                leftover_fill_size = data.len();
            }

            self.buffer[self.leftover..].copy_from_slice(&data[..leftover_fill_size]);
            self.leftover += leftover_fill_size;

            start_idx += leftover_fill_size;

            if self.leftover != BLOCK_SIZE {
                return;
            }

            self.inner.append_block(&self.buffer, false);
            self.leftover = 0;
        }

        for chunk in data[start_idx..].chunks(BLOCK_SIZE) {
            let len = chunk.len();
            self.buffer[..len].copy_from_slice(chunk);

            if len == BLOCK_SIZE {
                self.inner.append_block(&self.buffer, false);
            } else {
                self.leftover += len;
            }
        }
    }

    #[inline]
    fn leftover_pad16(&mut self) {
        if self.leftover != BLOCK_SIZE {
            self.buffer[self.leftover..].zeroize();
        }
    }

    /// Used mainly for AEAD construction, updates the Poly1305 state with padded data.
    pub fn update_leftover_pad16(&mut self) {
        if self.leftover == 0 {
            return;
        }

        self.leftover_pad16();
        self.inner.append_block(&self.buffer, false);
        self.leftover = 0;
    }

    /// Finalizes the Poly1305 state and returns the authentication tag.
    pub fn finalize(mut self) -> Tag {
        if self.leftover != 0 {
            self.buffer[self.leftover] = 0x01;
            self.leftover += 1;
            self.leftover_pad16();
            self.inner.append_block(&self.buffer, true);
        }

        self.inner.finish()
    }

    /// Verifies if the provided tag matches the computed Poly1305 tag.
    /// This perform `O(1)` comparasion of two tags
    pub fn verify(self, tag: &Tag) -> bool {
        let mut res: u8 = 1;

        for (a, b) in self.finalize().into_iter().zip(tag) {
            // perform constant time comparation

            black_box({
                // x will be 0 when a is equal b
                let x = a ^ b;

                // if they are equal, then x and -x will be the same as 0 and -0
                // otherwise x | -x with output a number with the msb set to 1
                // then just need to shift that bit back into the first position
                let y = (x | x.wrapping_neg()) >> 7;

                // now if the lsb is 1, the two number is not equal and vice versa.
                // to get the result, just need to flip it back
                // and do operation AND to the current state
                res &= y ^ 1;
            })
        }

        res == 1
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rfc_8439_example_vector() {
        let data = b"Cryptographic Forum Research Group";
        let key: Key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let expected: Tag = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(data);

        assert!(mac.verify(&expected));
    }

    #[test]
    fn rfc_8439_test_1() {
        let key: Key = Default::default();
        let data = [0u8; 16 * 4];
        let expected: Tag = Default::default();

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }

    #[test]
    fn rfc_8439_test_2() {
        let key: Key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96,
            0x22, 0x7a, 0x86, 0x3e,
        ];
        let data = [
            0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
            0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x69,
            0x6e, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
            0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
            0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
            0x20, 0x61, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72, 0x20, 0x70, 0x61, 0x72,
            0x74, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x49,
            0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
            0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79,
            0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6d, 0x61, 0x64,
            0x65, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
            0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
            0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x20, 0x69,
            0x73, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72, 0x65, 0x64, 0x20, 0x61,
            0x6e, 0x20, 0x22, 0x49, 0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x69,
            0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
            0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x69, 0x6e, 0x63,
            0x6c, 0x75, 0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20, 0x73, 0x74, 0x61, 0x74,
            0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
            0x20, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
            0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20, 0x77, 0x72, 0x69, 0x74, 0x74, 0x65,
            0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e,
            0x69, 0x63, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
            0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f, 0x72, 0x20, 0x70, 0x6c, 0x61, 0x63,
            0x65, 0x2c, 0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61,
            0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
        ];
        let expected: Tag = [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }
    #[test]
    fn rfc_8439_test_3() {
        let key: Key = [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let data = [
            0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
            0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x69,
            0x6e, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
            0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
            0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
            0x20, 0x61, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72, 0x20, 0x70, 0x61, 0x72,
            0x74, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20, 0x49,
            0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
            0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79,
            0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6d, 0x61, 0x64,
            0x65, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
            0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
            0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x20, 0x69,
            0x73, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72, 0x65, 0x64, 0x20, 0x61,
            0x6e, 0x20, 0x22, 0x49, 0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x69,
            0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
            0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x69, 0x6e, 0x63,
            0x6c, 0x75, 0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20, 0x73, 0x74, 0x61, 0x74,
            0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
            0x20, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
            0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20, 0x77, 0x72, 0x69, 0x74, 0x74, 0x65,
            0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e,
            0x69, 0x63, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
            0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f, 0x72, 0x20, 0x70, 0x6c, 0x61, 0x63,
            0x65, 0x2c, 0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61,
            0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
        ];
        let expected: Tag = [
            0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf, 0x89, 0xa6, 0xb8, 0x79, 0x4c, 0x31,
            0x0c, 0xf0,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }

    #[test]
    fn rfc_8439_test_4() {
        let key: Key = [
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ];
        let data = [
            0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c,
            0x20, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x6c, 0x69, 0x74, 0x68,
            0x79, 0x20, 0x74, 0x6f, 0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20, 0x67, 0x79,
            0x72, 0x65, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
            0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77, 0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41,
            0x6c, 0x6c, 0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77, 0x65, 0x72, 0x65, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65, 0x73, 0x2c,
            0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
            0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75, 0x74, 0x67, 0x72, 0x61, 0x62, 0x65,
            0x2e,
        ];
        let expected: Tag = [
            0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61, 0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5,
            0xeb, 0x62,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }

    // #[test]
    // fn rfc_8439_test_5() {
    //     let mut key: Key = Default::default();
    //     key[0] = 0x02;
    //     let data = [0xffu8; 16];
    //     let mut expected: Tag = Default::default();
    //     expected[0] = 0x03;

    //     let mut mac = Poly1305::new(&key);
    //     mac.update(&data);

    //     // assert!(mac.verify(&expected));
    //     let tag = mac.finalize();

    //     assert_eq!(tag, expected);
    // }

    #[test]
    fn rfc_8439_test_6() {
        let mut key: Key = Default::default();
        let mut data = [0u8; 16];
        let mut expected: Tag = Default::default();

        key[0] = 0x02;
        key[16..].copy_from_slice(&[0xff; 16]);
        data[0] = 0x02;
        expected[0] = 0x03;

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }
    #[test]
    fn rfc_8439_test_7() {
        let mut key: Key = Default::default();
        let data = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut expected: Tag = Default::default();

        key[0] = 0x01;
        expected[0] = 0x05;

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }

    #[test]
    fn rfc_8439_test_8() {
        let mut key: Key = Default::default();
        let data = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFB, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
            0xFE, 0xFE, 0xFE, 0xFE, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        let expected: Tag = Default::default();

        key[0] = 0x01;

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }
    #[test]
    fn rfc_8439_test_9() {
        let mut key: Key = Default::default();
        let mut data = [0xffu8; 16];
        let mut expected: Tag = [0xffu8; 16];

        key[0] = 0x02;
        data[0] = 0xfd;
        expected[0] = 0xfa;

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }
    #[test]
    fn rfc_8439_test_10() {
        let key: Key = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let data = [
            0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected: Tag = [
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }

    #[test]
    fn rfc_8439_test_11() {
        let key: Key = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let data = [
            0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected: Tag = [
            0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut mac = Poly1305::new(&key);
        mac.update(&data);

        assert!(mac.verify(&expected));
    }
}
