use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::PUBKEY_BYTES;

pub const SESSION_KEY_EXPIRATION_LIMIT: u64 = 3 * 30 * 24 * 60 * 60; // 3 months in seconds

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod, Default)]
#[repr(C)]
pub struct SessionKey {
    pub key: [u8; PUBKEY_BYTES],
    pub expiration: u64,
}
