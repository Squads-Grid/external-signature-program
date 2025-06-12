use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    utils::signatures::ClientDataJsonReconstructionParams,
    utils::{hash, SmallVec},
};

use super::{CompressedP256PublicKey, RpIdInformation};

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256RawInitializationData {
    pub rp_id: SmallVec<u8, u8>,
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
#[repr(C)]
pub struct P256ParsedInitializationData {
    pub rp_id_info: RpIdInformation,
    pub public_key: CompressedP256PublicKey,
    pub counter: u64,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

impl From<P256RawInitializationData> for P256ParsedInitializationData {
    fn from(data: P256RawInitializationData) -> Self {
        let rp_id_hash = hash(&data.rp_id.as_slice());
        Self {
            rp_id_info: RpIdInformation::new(data.rp_id.as_slice(), rp_id_hash),
            public_key: CompressedP256PublicKey::new(&data.public_key),
            // Set to 0 since we're initializing the account
            counter: 0,
            client_data_json_reconstruction_params: data.client_data_json_reconstruction_params,
        }
    }
}
