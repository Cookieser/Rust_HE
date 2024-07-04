use std::slice;

use sha2::Digest;

const HASH_BLOCK_U64_COUNT: usize = 4;

pub type HashBlock = [u64; HASH_BLOCK_U64_COUNT];

pub const HASH_ZERO_BLOCK: HashBlock = [0; HASH_BLOCK_U64_COUNT];

#[inline]
pub fn hash(input: &[u64], destination: &mut HashBlock) {
    let mut hasher = sha2::Sha256::new();
    unsafe {
        let len = input.len() * 8;
        let ptr = input.as_ptr() as *const u8;
        let sl = slice::from_raw_parts(ptr, len);
        hasher.update(sl);
        let out = hasher.finalize();
        let sl = slice::from_raw_parts(out.as_ptr() as *const u64, 4);
        destination[..HASH_BLOCK_U64_COUNT].copy_from_slice(&sl[..HASH_BLOCK_U64_COUNT]);
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_hash() {
        let data = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let mut hashed = HASH_ZERO_BLOCK;
        hash(&data, &mut hashed);
        assert_eq!(
            hashed,
            [0xc91516ef25e48a80, 0x800f0651aad1f12c, 0x52396646e3748df1, 0xfa6485cfcd94ff4e],
        );
    }
}