use super::*;
use zeroize::Zeroize as _;

#[derive(Clone)]
pub(crate) struct Poly1305Inner {
    r: [u64; 3],
    h: [u64; 3],
    state: [u64; 2],
}

impl Drop for Poly1305Inner {
    fn drop(&mut self) {
        self.r.zeroize();
        self.h.zeroize();
        self.state.zeroize();
    }
}

impl Poly1305Inner {
    pub(crate) fn new(key: &Key) -> Self {
        let r_u64_1 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let r_u64_2 = u64::from_le_bytes(key[8..16].try_into().unwrap());

        let r = [
            r_u64_1 & 0xffc0fffffff,
            ((r_u64_1 >> 44) | (r_u64_2 << 20)) & 0xfffffc0ffff,
            (r_u64_2 >> 24) & 0x00ffffffc0f,
        ];

        let state = [
            u64::from_le_bytes(key[16..24].try_into().unwrap()),
            u64::from_le_bytes(key[24..32].try_into().unwrap()),
        ];

        Self {
            r,
            h: Default::default(),
            state,
        }
    }

    #[rustfmt::skip]
    #[inline]
    pub(crate) fn append_block(&mut self, block: &Block, is_final: bool) {
        let hibit = if is_final { 0 } else { 1u64 << 40 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let s1 = r1 * (5 << 2);
        let s2 = r2 * (5 << 2);

        // h += m[i]
        let t0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(block[8..].try_into().unwrap());

        h0 += t0 & 0xfffffffffff;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
        h2 += ((t1 >> 24) & 0x3ffffffffff) | hibit;

        /* h *= r */
        let d0     = mul_u64(h0, r0) + mul_u64(h1, s2) + mul_u64(h2, s1);
        let mut d1 = mul_u64(h0, r1) + mul_u64(h1, r0) + mul_u64(h2, s2);
        let mut d2 = mul_u64(h0, r2) + mul_u64(h1, r1) + mul_u64(h2, r0);

		/* (partial) h %= p */
        let mut c: u64;

        c = (d0 >> 44) as u64;
        h0 = d0 as u64 & 0xfffffffffff;
        d1 += u128::from(c);

        c = (d1 >> 44) as u64;
        h1 = d1 as u64 & 0xfffffffffff;
        d2 += u128::from(c);

        c = (d2 >> 42) as u64;
        h2 = d2 as u64 & 0x3ffffffffff;
        h0 += c * 5;

        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;
        
        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    #[inline]
    pub(crate) fn finish(self) -> Tag {
        /* fully carry h */
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let mut c: u64;

        c = h1 >> 44;
        h1 &= 0xfffffffffff;

        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;

        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;

        h1 += c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;

        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;

        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;

        h1 += c;

        /* compute h + -p */
        let mut g0 = h0.wrapping_add(c);
        c = g0 >> 44;
        g0 &= 0xfffffffffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 44;
        g1 &= 0xfffffffffff;

        let mut g2 = h2.wrapping_add(c).wrapping_sub(1u64 << 42);

        /* select h if h < p, or h + -p if h >= p */
        c = (g2 >> (64 - 1)).wrapping_sub(1);
        g0 &= c;
        g1 &= c;
        g2 &= c;
        c = !c;
        h0 = (h0 & c) | g0;
        h1 = (h1 & c) | g1;
        h2 = (h2 & c) | g2;

        /* h = (h + pad) */
        let t0 = self.state[0];
        let t1 = self.state[1];

        h0 += t0 & 0xfffffffffff;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;

        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;

        h2 += ((t1 >> 24) & 0x3ffffffffff) + c;
        h2 &= 0x3ffffffffff;

        /* mac = h % (2^128) */
        h0 |= h1 << 44;
        h1 = (h1 >> 20) | (h2 << 24);

        let mut mac: Tag = Default::default();
        mac[..8].copy_from_slice(&h0.to_le_bytes());
        mac[8..].copy_from_slice(&h1.to_le_bytes());
        mac
    }
}

#[inline(always)]
fn mul_u64(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}
