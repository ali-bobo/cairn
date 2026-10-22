//! Deterministic input generator for "never panics" tests of parsers that read
//! attacker-controlled bytes or text (prefetch, version resources, RMM logs, LNK,
//! command history, registry values, encoded commands). Test-only: compiled under the
//! `test-util` feature, which crates enable from `[dev-dependencies]` only.
//!
//! A seeded xorshift generator instead of a property-testing framework: no new
//! dependency in a forensic tool's supply chain, fully reproducible (a failing case is
//! re-run from its iteration number), and fast enough to run thousands of cases per
//! parser in the normal test suite.

/// xorshift64* pseudo-random generator. Not cryptographic; reproducible from its seed.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }

    /// Random bytes, length in `0..=max_len`, biased towards the values parsers treat
    /// specially (0x00, 0xFF, 0x80, ASCII separators, high offsets).
    pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        const SPECIAL: &[u8] = &[
            0x00, 0xFF, 0x80, 0x7F, b'\\', b'/', b'"', b'\n', b'\r', b'%',
        ];
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| {
                if self.below(4) == 0 {
                    SPECIAL[self.below(SPECIAL.len())]
                } else {
                    self.next_u64() as u8
                }
            })
            .collect()
    }

    /// Text built from fragments parsers look for (quotes, separators, keywords handed
    /// in by the caller) mixed with random and multi-byte characters.
    pub fn text(&mut self, max_parts: usize, fragments: &[&str]) -> String {
        const BASE: &[&str] = &[
            "\"", "'", " ", "\t", "\\", "/", ":", "=", "-", "%", "\0", "\r\n", "文", "é", "😀",
            "\u{FFFD}", "\u{202E}", "C:\\", "\\\\", "..",
        ];
        let parts = self.below(max_parts + 1);
        let mut s = String::new();
        for _ in 0..parts {
            match self.below(3) {
                0 if !fragments.is_empty() => s.push_str(fragments[self.below(fragments.len())]),
                1 => s.push_str(BASE[self.below(BASE.len())]),
                _ => {
                    let c = char::from_u32(self.below(0x3000) as u32).unwrap_or('x');
                    s.push(c);
                }
            }
        }
        s
    }

    /// `seed` with a few random edits: byte flips, truncation, extension, and u32
    /// fields overwritten with boundary values (0, u32::MAX, lengths just past the end).
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..=self.below(8) {
            match self.below(5) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = self.next_u64() as u8;
                }
                1 => {
                    let cut = self.below(v.len() + 1);
                    v.truncate(cut);
                }
                2 => {
                    let extra = self.bytes(64);
                    v.extend_from_slice(&extra);
                }
                3 if v.len() >= 4 => {
                    let i = self.below(v.len() - 3);
                    let val: u32 = match self.below(4) {
                        0 => 0,
                        1 => u32::MAX,
                        2 => v.len() as u32,
                        _ => (v.len() as u32).wrapping_add(self.below(16) as u32),
                    };
                    v[i..i + 4].copy_from_slice(&val.to_le_bytes());
                }
                _ => {}
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let (mut a, mut b) = (Rng::new(7), Rng::new(7));
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(Rng::new(0).next_u64(), 0, "zero seed is usable");
    }

    #[test]
    fn mutate_and_bytes_respect_bounds() {
        let mut r = Rng::new(3);
        for _ in 0..1000 {
            assert!(r.bytes(16).len() <= 16);
            let m = r.mutate(b"0123456789");
            assert!(m.len() <= 10 + 64 * 9);
            let _ = r.text(8, &["x"]);
        }
    }
}
