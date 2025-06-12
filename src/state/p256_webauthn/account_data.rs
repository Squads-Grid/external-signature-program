use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};

use crate::{
    state::{AccountHeader, SessionKey},
    utils::HASH_LENGTH,
};

/// P-256 (secp256r1) account data
#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct P256WebauthnAccountData {
    /// Exists here purely for alignment
    _header: AccountHeader,

    /// Relying Party ID information
    pub rp_id_info: RpIdInformation,

    /// P-256 public key (compressed)
    pub public_key: CompressedP256PublicKey,

    /// Padding to ensure alignment
    pub padding: [u8; 2],

    /// Session key
    pub session_key: SessionKey,

    // Webauthn signature counter (used mostly by hardware security keys)
    pub counter: u64,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct RpIdInformation {
    pub rp_id_len: u8,
    pub rp_id: [u8; 32],
    pub rp_id_hash: [u8; 32],
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct CompressedP256PublicKey {
    pub x: [u8; 32],
    pub y_parity: u8,
}

impl RpIdInformation {
    pub fn new(rp_id: &[u8], rp_id_hash: [u8; HASH_LENGTH]) -> Self {
        Self {
            rp_id_len: rp_id.len() as u8,
            rp_id: {
                let mut fixed_rp_id = [0u8; 32];
                fixed_rp_id[..rp_id.len()].copy_from_slice(&rp_id);
                fixed_rp_id
            },
            rp_id_hash: rp_id_hash,
        }
    }
}

impl CompressedP256PublicKey {
    pub fn new(public_key: &[u8]) -> Self {
        Self {
            x: public_key[1..33].try_into().unwrap(),
            y_parity: public_key[0],
        }
    }
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = self.y_parity;
        bytes[1..33].copy_from_slice(&self.x);
        bytes
    }
}
