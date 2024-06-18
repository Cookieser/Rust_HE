use rand::{SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;
use crate::util::basic::HE_PRNG_SEED_BYTES;
use blake3;

#[derive(Copy, Clone)]
pub struct PRNGSeed(pub [u8; HE_PRNG_SEED_BYTES]);

impl Default for PRNGSeed {
    fn default() -> Self {
        PRNGSeed([0; 64])
    }
}

impl AsMut<[u8]> for PRNGSeed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for PRNGSeed {
    fn as_ref(self: &PRNGSeed) -> &[u8] {&self.0}
}

pub struct BlakeRNGFactory {
    use_random_seed: bool,
    seed: PRNGSeed,
}

impl Default for BlakeRNGFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BlakeRNGFactory {
    pub fn new() -> Self {
        Self {
            use_random_seed: true,
            seed: PRNGSeed::default(),
        }
    }

    #[allow(unused)]
    pub fn from_seed(seed: PRNGSeed) -> Self {
        Self {
            use_random_seed: false,
            seed,
        }
    }

    #[allow(unused)]
    pub fn set_seed(&mut self, seed: PRNGSeed) {
        self.seed = seed;
    }

    pub fn get_rng(&self) -> BlakeRNG {
        if self.use_random_seed {
            let mut seed = [0; 64];
            ChaCha20Rng::from_entropy().fill_bytes(&mut seed);
            BlakeRNG::from_seed(PRNGSeed(seed))
        } else {
            BlakeRNG::from_seed(self.seed)
        }
    }

    pub fn get_rng_rc(&self) -> BlakeRNG {
        self.get_rng()
    }
}

const BUFFER_SIZE: usize = 4096;

#[repr(align(8))]
pub struct BlakeRNG {
    buffer: [u8; BUFFER_SIZE],
    seed: PRNGSeed,
    counter: u64,
    buffer_current: usize,
}

impl SeedableRng for BlakeRNG {
    type Seed = PRNGSeed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0; BUFFER_SIZE],
            buffer_current: BUFFER_SIZE,
        }
    }

}

impl BlakeRNG {
    
    fn refill_buffer(&mut self) {
        let mut hash = blake3::Hasher::new();
        hash.update(self.seed.as_ref());
        hash.update(&self.counter.to_le_bytes());
        hash.finalize_xof().fill(&mut self.buffer);
        self.buffer_current = 0;
        self.counter = self.counter.wrapping_add(1);
    }

}

impl RngCore for BlakeRNG {

    fn next_u32(&mut self) -> u32 {
        self.buffer_current = (self.buffer_current + 3) & !3; // align to 4 bytes
        if self.buffer_current + 4 > BUFFER_SIZE {
            self.refill_buffer();
        }
        unsafe {
            let ret = *(self.buffer.as_ptr().add(self.buffer_current) as *const u32);
            self.buffer_current += 4;
            ret
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.buffer_current = (self.buffer_current + 7) & !7; // align to 8 bytes
        if self.buffer_current + 8 > BUFFER_SIZE {
            self.refill_buffer();
        }
        unsafe {
            let ret = *(self.buffer.as_ptr().add(self.buffer_current) as *const u64);
            self.buffer_current += 8;
            ret
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            if self.buffer_current >= BUFFER_SIZE {
                self.refill_buffer();
            }
            let len = std::cmp::min(dest.len() - i, BUFFER_SIZE - self.buffer_current);
            dest[i..i+len].copy_from_slice(&self.buffer[self.buffer_current..self.buffer_current+len]);
            i += len;
            self.buffer_current += len;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake_rng() {
        let mut rng = BlakeRNG::from_seed(PRNGSeed([1; 64]));
        let mut rng2 = BlakeRNG::from_seed(PRNGSeed([1; 64]));
        for _ in 0..100 {
            assert_eq!(rng.next_u32(), rng2.next_u32());
            assert_eq!(rng.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_blake_rng_factory() {
        let factory = BlakeRNGFactory::from_seed(PRNGSeed([1; 64]));
        let mut rng = factory.get_rng();
        let mut rng2 = factory.get_rng();
        for _ in 0..100 {
            assert_eq!(rng.next_u32(), rng2.next_u32());
            assert_eq!(rng.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_blake_rng_factory_randomized() {
        let factory = BlakeRNGFactory::new();
        let mut rng = factory.get_rng();
        let mut rng2 = factory.get_rng();
        for _ in 0..100 {
            assert_ne!(rng.next_u32(), rng2.next_u32());
            assert_ne!(rng.next_u64(), rng2.next_u64());
        }
    }

}