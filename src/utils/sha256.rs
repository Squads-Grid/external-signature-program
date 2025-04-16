use core::mem::MaybeUninit;
use pinocchio::syscalls::sol_sha256;

pub const HASH_LENGTH: usize = 32;

#[inline(always)]
pub fn hash(data: &[u8]) -> [u8; HASH_LENGTH] {
    hashv(&[data])
}

#[inline(always)]
pub fn hashv(data: &[&[u8]]) -> [u8; HASH_LENGTH] {
    let mut out = MaybeUninit::<[u8; HASH_LENGTH]>::uninit();
    unsafe {
        hash_into(data, out.as_mut_ptr());
        out.assume_init()
    }
}

#[inline(always)]
pub fn hash_into(data: &[&[u8]], out: *mut [u8; 32]) {
    #[cfg(target_os = "solana")]
    unsafe {
        sol_sha256(
            data as *const _ as *const u8,
            data.len() as u64,
            out as *mut u8,
        );
    }
}
