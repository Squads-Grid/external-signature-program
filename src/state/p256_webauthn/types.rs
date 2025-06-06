use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::Pubkey;

use crate::{
    signatures::ClientDataJsonReconstructionParams,
    state::{CompressedP256PublicKey, RpIdInformation},
    utils::{hash, SmallVec},
};

pub struct P256WebauthnDeriveAccountArgs {
    pub public_key: [u8; 33],
}

impl<'a> From<&'a P256WebauthnParsedInitializationData> for P256WebauthnDeriveAccountArgs {
    fn from(data: &P256WebauthnParsedInitializationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

impl<'a> From<&'a P256WebauthnParsedVerificationData> for P256WebauthnDeriveAccountArgs {
    fn from(data: &P256WebauthnParsedVerificationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256WebauthnRawInitializationData {
    pub rp_id: SmallVec<u8, u8>,
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
    pub session_key: Option<SessionKey>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod, Default)]
#[repr(C)]
pub struct SessionKey {
    pub key: Pubkey,
    pub expiration: u64,
}

impl From<P256WebauthnRawInitializationData> for P256WebauthnParsedInitializationData {
    fn from(data: P256WebauthnRawInitializationData) -> Self {
        let rp_id_hash = hash(&data.rp_id.as_slice());
        Self {
            rp_id_info: RpIdInformation::new(data.rp_id.as_slice(), rp_id_hash),
            public_key: CompressedP256PublicKey::new(&data.public_key),
            counter: 0,
            client_data_json_reconstruction_params: data.client_data_json_reconstruction_params,
            session_key: data.session_key.unwrap_or_default(),
        }
    }
}
pub struct P256WebauthnParsedInitializationData {
    pub rp_id_info: RpIdInformation,
    pub public_key: CompressedP256PublicKey,
    pub counter: u64,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
    pub session_key: SessionKey,
}

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256WebauthnRawVerificationData {
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

impl From<P256WebauthnRawVerificationData> for P256WebauthnParsedVerificationData {
    fn from(data: P256WebauthnRawVerificationData) -> Self {
        Self {
            public_key: CompressedP256PublicKey::new(&data.public_key),
            client_data_json_reconstruction_params: data.client_data_json_reconstruction_params,
        }
    }
}
pub struct P256WebauthnParsedVerificationData {
    pub public_key: CompressedP256PublicKey,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}
