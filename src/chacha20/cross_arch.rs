use super::*;
use zeroize::Zeroize;

type State = [u32; STATE_BLOCK_SIZE];

#[derive(Clone)]
pub struct ChaCha20Inner {
    state: State,
}

impl Drop for ChaCha20Inner {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl ChaCha20Inner {
    #[inline]
    pub(crate) fn new_with_cnt(key: &Key, nonce: &Nonce, cnt: u32) -> Self {
        let keys_u32 = key
            .chunks_exact(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()));

        let nonces_u32 = nonce
            .chunks_exact(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()));

        let mut state = [0; STATE_BLOCK_SIZE];

        state[0..4].copy_from_slice(&INIT_CONSTANTS);
        state[4..12]
            .iter_mut()
            .zip(keys_u32)
            .for_each(|(val, key)| *val = key);
        state[12] = cnt;
        state[13..16]
            .iter_mut()
            .zip(nonces_u32)
            .for_each(|(val, nonce)| *val = nonce);

        Self { state }
    }

    #[inline(always)]
    pub(crate) fn seek_to(&mut self, position: u32) {
        self.state[12] = position;
    }

    #[inline(always)]
    pub(crate) fn current_position(&self) -> u32 {
        self.state[12]
    }

    #[inline(always)]
    pub(crate) fn gen_block(&mut self, block: &mut Block) {
        let output = self.full_round();
        // Increase the counter by one (modulo 2^32)
        self.state[12] = self.state[12].wrapping_add(1);

        let serialized_output = output.into_iter().flat_map(|v| v.to_le_bytes());

        block
            .iter_mut()
            .zip(serialized_output)
            .for_each(|(s1, s0)| *s1 = s0);
    }

    #[inline(always)]
    pub(crate) fn full_round(&self) -> State {
        let mut working_state = self.state;

        // column round + diagonal round
        for _ in 0..(NUMBER_OF_ROUND / 2) {
            // column rounds
            quarter_round(&mut working_state, 0, 4, 8, 12);
            quarter_round(&mut working_state, 1, 5, 9, 13);
            quarter_round(&mut working_state, 2, 6, 10, 14);
            quarter_round(&mut working_state, 3, 7, 11, 15);

            // diagonal rounds
            quarter_round(&mut working_state, 0, 5, 10, 15);
            quarter_round(&mut working_state, 1, 6, 11, 12);
            quarter_round(&mut working_state, 2, 7, 8, 13);
            quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        working_state
            .iter_mut()
            .zip(&self.state)
            .for_each(|(s1, s0)| *s1 = s1.wrapping_add(*s0));

        working_state
    }
}

#[inline(always)]
pub(self) fn quarter_round(state: &mut State, a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn test_quarter_round() {
        let mut state: State = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
        ];

        let expected: State = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
            0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
        ];

        quarter_round(&mut state, 2, 7, 8, 13);

        assert_eq!(state, expected);
    }

    #[test]
    #[rustfmt::skip]
    fn test_full_round() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let ctx = ChaCha20Inner::new_with_cnt(&key, &nonce, 1);

        let expected_state: State = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(ctx.full_round(), expected_state);
    }
}
