use core::mem::MaybeUninit;

pub const HASH_LENGTH: usize = 32;

#[inline(always)]
// Simple wrapper around hashv to hash a single slice
pub fn hash(data: &[u8]) -> [u8; HASH_LENGTH] {
    hashv(&[data])
}

#[inline(always)]
// Simple wrapper around the hashv syscall to hash multiple slices
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    let mut out = MaybeUninit::<[u8; HASH_LENGTH]>::uninit();
    unsafe {
        hash_into(data, out.as_mut_ptr());
        out.assume_init()
    }
}

#[inline(always)]
#[allow(unused)]
// Simple wrapper around the hashv syscall
pub unsafe fn hash_into(data: &[&[u8]], out: *mut [u8; 32]) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_sha256(
            data as *const _ as *const u8,
            data.len() as u64,
            out as *mut u8,
        );
    }
}
