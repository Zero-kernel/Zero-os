//! Shared cryptographic primitives for Zero-OS kernel.
//!
//! R148-I9 FIX: Consolidates duplicate SHA-256 implementations from the audit
//! and livepatch subsystems into a single canonical FIPS 180-4 implementation.
//! This eliminates maintenance drift risk and ensures both subsystems use the
//! same KAT-validated code path.

#![no_std]

/// SHA-256 (FIPS 180-4) implementation for no_std kernel environment.
pub mod sha256 {
    /// SHA-256 round constants (FIPS 180-4, Section 4.2.2)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    /// SHA-256 initial hash values (FIPS 180-4, Section 5.3.3)
    const INIT_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    /// SHA-256 block size in bytes.
    pub const BLOCK_SIZE: usize = 64;

    /// SHA-256 digest size in bytes.
    pub const DIGEST_SIZE: usize = 32;

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn small_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn small_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    /// Streaming SHA-256 hasher.
    #[derive(Clone)]
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }

    impl Sha256 {
        /// Create a new SHA-256 hasher.
        pub const fn new() -> Self {
            Self {
                state: INIT_STATE,
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        /// Compute SHA-256 digest of a single message.
        pub fn digest(data: &[u8]) -> [u8; 32] {
            let mut hasher = Self::new();
            hasher.update(data);
            hasher.finalize()
        }

        /// Feed more data into the hasher.
        pub fn update(&mut self, data: &[u8]) {
            let mut input = data;

            while !input.is_empty() {
                let take = core::cmp::min(64 - self.buffer_len, input.len());
                self.buffer[self.buffer_len..self.buffer_len + take]
                    .copy_from_slice(&input[..take]);
                self.buffer_len += take;
                self.total_len = self.total_len.wrapping_add(take as u64);

                if self.buffer_len == 64 {
                    let block = self.buffer;
                    self.compress_block(&block);
                    self.buffer_len = 0;
                }
                input = &input[take..];
            }
        }

        /// Finalize and return the 32-byte digest. Consumes the hasher.
        pub fn finalize(mut self) -> [u8; 32] {
            let total_bits = self.total_len.wrapping_mul(8);

            // Pad with 0x80
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;

            // If not enough room for the 8-byte length, pad and compress
            if self.buffer_len > 56 {
                for i in self.buffer_len..64 {
                    self.buffer[i] = 0;
                }
                let block = self.buffer;
                self.compress_block(&block);
                self.buffer_len = 0;
            }

            // Pad with zeros until length field position
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }

            // Append bit length in big-endian
            self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
            let block = self.buffer;
            self.compress_block(&block);

            // Output state in big-endian
            let mut out = [0u8; 32];
            for (i, chunk) in out.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }

        /// Compress a single 512-bit block.
        #[inline(always)]
        fn compress_block(&mut self, block: &[u8; 64]) {
            // Message schedule
            let mut w = [0u32; 64];
            for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
                w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            for i in 16..64 {
                w[i] = small_sigma1(w[i - 2])
                    .wrapping_add(w[i - 7])
                    .wrapping_add(small_sigma0(w[i - 15]))
                    .wrapping_add(w[i - 16]);
            }

            // Working variables
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];

            // 64 rounds
            for i in 0..64 {
                let t1 = h
                    .wrapping_add(big_sigma1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            // Update state
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }
}
