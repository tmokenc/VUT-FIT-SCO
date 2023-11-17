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
        
//         // (partial) h %= p
//         let mut c: u32;
//         c = (d0 >> 26) as u32;
//         h0 = d0 as u32 & 0x3ff_ffff;
//         d1 += u64::from(c);
//
//         c = (d1 >> 26) as u32;
//         h1 = d1 as u32 & 0x3ff_ffff;
//         d2 += u64::from(c);
//
//         c = (d2 >> 26) as u32;
//         h2 = d2 as u32 & 0x3ff_ffff;
//         d3 += u64::from(c);
//
//         c = (d3 >> 26) as u32;
//         h3 = d3 as u32 & 0x3ff_ffff;
//         d4 += u64::from(c);
//
//         c = (d4 >> 26) as u32;
//         h4 = d4 as u32 & 0x3ff_ffff;
//         h0 += c * 5;
//
//         c = h0 >> 26;
//         h0 &= 0x3ff_ffff;
//         h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    #[inline]
    pub(crate) fn finish(self) -> Tag {
        // fn print(a: &u64) { println!("{:x}", a)}
        // self.h.iter().for_each(print);
        // self.r.iter().for_each(print);
        // self.state.iter().for_each(print);
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

// #[derive(Clone, Default)]
// pub(crate) struct Poly1305Inner {
//     r: [u32; 5],
//     h: [u32; 5],
//     pad: [u32; 4],
// }
//
// impl Drop for Poly1305Inner {
//     fn drop(&mut self) {
//         self.r.zeroize();
//         self.h.zeroize();
//         self.pad.zeroize();
//     }
// }
//
// impl Poly1305Inner {
//     pub(crate) fn new(key: &Key) -> Self {
//         let mut poly = Self::default();
//
//         // r &= 0xffffffc0ffffffc0ffffffc0fffffff
//         poly.r[0] = (u32::from_le_bytes(key[0..4].try_into().unwrap())) & 0x3ff_ffff;
//         poly.r[1] = (u32::from_le_bytes(key[3..7].try_into().unwrap()) >> 2) & 0x3ff_ff03;
//         poly.r[2] = (u32::from_le_bytes(key[6..10].try_into().unwrap()) >> 4) & 0x3ff_c0ff;
//         poly.r[3] = (u32::from_le_bytes(key[9..13].try_into().unwrap()) >> 6) & 0x3f0_3fff;
//         poly.r[4] = (u32::from_le_bytes(key[12..16].try_into().unwrap()) >> 8) & 0x00f_ffff;
//
//         poly.pad[0] = u32::from_le_bytes(key[16..20].try_into().unwrap());
//         poly.pad[1] = u32::from_le_bytes(key[20..24].try_into().unwrap());
//         poly.pad[2] = u32::from_le_bytes(key[24..28].try_into().unwrap());
//         poly.pad[3] = u32::from_le_bytes(key[28..32].try_into().unwrap());
//
//         poly
//     }
//
//     #[rustfmt::skip]
//     #[inline]
//     pub(crate) fn append_block(&mut self, block: &Block, is_final: bool) {
//         let hibit = if is_final { 0 } else { 1 << 24 };
//
//         let r0 = self.r[0];
//         let r1 = self.r[1];
//         let r2 = self.r[2];
//         let r3 = self.r[3];
//         let r4 = self.r[4];
//
//         let s1 = r1 * 5;
//         let s2 = r2 * 5;
//         let s3 = r3 * 5;
//         let s4 = r4 * 5;
//
//         let mut h0 = self.h[0];
//         let mut h1 = self.h[1];
//         let mut h2 = self.h[2];
//         let mut h3 = self.h[3];
//         let mut h4 = self.h[4];
//
//         // h += m
//         h0 += (u32::from_le_bytes(block[0..4].try_into().unwrap())) & 0x3ff_ffff;
//         h1 += (u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
//         h2 += (u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4) & 0x3ff_ffff;
//         h3 += (u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6) & 0x3ff_ffff;
//         h4 += (u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8) | hibit;
//
//         // h *= r
//         let d0 = (u64::from(h0) * u64::from(r0))
//             + (u64::from(h1) * u64::from(s4))
//             + (u64::from(h2) * u64::from(s3))
//             + (u64::from(h3) * u64::from(s2))
//             + (u64::from(h4) * u64::from(s1));
//
//         let mut d1 = (u64::from(h0) * u64::from(r1))
//             + (u64::from(h1) * u64::from(r0))
//             + (u64::from(h2) * u64::from(s4))
//             + (u64::from(h3) * u64::from(s3))
//             + (u64::from(h4) * u64::from(s2));
//
//         let mut d2 = (u64::from(h0) * u64::from(r2))
//             + (u64::from(h1) * u64::from(r1))
//             + (u64::from(h2) * u64::from(r0))
//             + (u64::from(h3) * u64::from(s4))
//             + (u64::from(h4) * u64::from(s3));
//
//         let mut d3 = (u64::from(h0) * u64::from(r3))
//             + (u64::from(h1) * u64::from(r2))
//             + (u64::from(h2) * u64::from(r1))
//             + (u64::from(h3) * u64::from(r0))
//             + (u64::from(h4) * u64::from(s4));
//
//         let mut d4 = (u64::from(h0) * u64::from(r4))
//             + (u64::from(h1) * u64::from(r3))
//             + (u64::from(h2) * u64::from(r2))
//             + (u64::from(h3) * u64::from(r1))
//             + (u64::from(h4) * u64::from(r0));
//
//         // (partial) h %= p
//         let mut c: u32;
//         c = (d0 >> 26) as u32;
//         h0 = d0 as u32 & 0x3ff_ffff;
//         d1 += u64::from(c);
//
//         c = (d1 >> 26) as u32;
//         h1 = d1 as u32 & 0x3ff_ffff;
//         d2 += u64::from(c);
//
//         c = (d2 >> 26) as u32;
//         h2 = d2 as u32 & 0x3ff_ffff;
//         d3 += u64::from(c);
//
//         c = (d3 >> 26) as u32;
//         h3 = d3 as u32 & 0x3ff_ffff;
//         d4 += u64::from(c);
//
//         c = (d4 >> 26) as u32;
//         h4 = d4 as u32 & 0x3ff_ffff;
//         h0 += c * 5;
//
//         c = h0 >> 26;
//         h0 &= 0x3ff_ffff;
//         h1 += c;
//
//         self.h[0] = h0;
//         self.h[1] = h1;
//         self.h[2] = h2;
//         self.h[3] = h3;
//         self.h[4] = h4;
//     }
//
//     #[inline]
//     pub(crate) fn finish(&mut self) -> Tag {
//         // fully carry h
//         let mut h0 = self.h[0];
//         let mut h1 = self.h[1];
//         let mut h2 = self.h[2];
//         let mut h3 = self.h[3];
//         let mut h4 = self.h[4];
//
//         let mut c: u32;
//         c = h1 >> 26;
//         h1 &= 0x3ff_ffff;
//         h2 += c;
//
//         c = h2 >> 26;
//         h2 &= 0x3ff_ffff;
//         h3 += c;
//
//         c = h3 >> 26;
//         h3 &= 0x3ff_ffff;
//         h4 += c;
//
//         c = h4 >> 26;
//         h4 &= 0x3ff_ffff;
//         h0 += c * 5;
//
//         c = h0 >> 26;
//         h0 &= 0x3ff_ffff;
//         h1 += c;
//
//         // compute h + -p
//         let mut g0 = h0.wrapping_add(5);
//         c = g0 >> 26;
//         g0 &= 0x3ff_ffff;
//
//         let mut g1 = h1.wrapping_add(c);
//         c = g1 >> 26;
//         g1 &= 0x3ff_ffff;
//
//         let mut g2 = h2.wrapping_add(c);
//         c = g2 >> 26;
//         g2 &= 0x3ff_ffff;
//
//         let mut g3 = h3.wrapping_add(c);
//         c = g3 >> 26;
//         g3 &= 0x3ff_ffff;
//
//         let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
//
//         // select h if h < p, or h + -p if h >= p
//         let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
//         g0 &= mask;
//         g1 &= mask;
//         g2 &= mask;
//         g3 &= mask;
//         g4 &= mask;
//         mask = !mask;
//         h0 = (h0 & mask) | g0;
//         h1 = (h1 & mask) | g1;
//         h2 = (h2 & mask) | g2;
//         h3 = (h3 & mask) | g3;
//         h4 = (h4 & mask) | g4;
//
//         // h = h % (2^128)
//         h0 |= h1 << 26;
//         h1 = (h1 >> 6) | (h2 << 20);
//         h2 = (h2 >> 12) | (h3 << 14);
//         h3 = (h3 >> 18) | (h4 << 8);
//
//         // h = mac = (h + pad) % (2^128)
//         let mut f: u64;
//         f = u64::from(h0) + u64::from(self.pad[0]);
//         h0 = f as u32;
//
//         f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
//         h1 = f as u32;
//
//         f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
//         h2 = f as u32;
//
//         f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
//         h3 = f as u32;
//
//         let mut tag = Block::default();
//         tag[0..4].copy_from_slice(&h0.to_le_bytes());
//         tag[4..8].copy_from_slice(&h1.to_le_bytes());
//         tag[8..12].copy_from_slice(&h2.to_le_bytes());
//         tag[12..16].copy_from_slice(&h3.to_le_bytes());
//
//         tag
//     }
// }
