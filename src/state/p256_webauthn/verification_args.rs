use borsh::{BorshDeserialize, BorshSerialize};

use crate::utils::signatures::ClientDataJsonReconstructionParams;

use super::CompressedP256PublicKey;

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256RawVerificationData {
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256ParsedVerificationData {
    pub public_key: CompressedP256PublicKey,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

impl From<P256RawVerificationData> for P256ParsedVerificationData {
    fn from(data: P256RawVerificationData) -> Self {
        Self {
            public_key: CompressedP256PublicKey::new(&data.public_key),
            client_data_json_reconstruction_params: data.client_data_json_reconstruction_params,
        }
    }
}
