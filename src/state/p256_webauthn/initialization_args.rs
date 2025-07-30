use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;

use crate::{
    errors::ExternalSignatureProgramError,
    utils::{hash, signatures::ClientDataJsonReconstructionParams, SmallVec},
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

impl TryFrom<P256RawInitializationData> for P256ParsedInitializationData {
    type Error = ProgramError;

    fn try_from(data: P256RawInitializationData) -> Result<Self, ProgramError> {
        if data.rp_id.len() > 32 {
            return Err(ExternalSignatureProgramError::P256RelyingPartTooLong.into());
        }
        if data.rp_id.as_slice().contains(&b'"') {
            return Err(ExternalSignatureProgramError::P256RelyingPartIncludeQuotes.into());
        }
        let rp_id_hash = hash(&data.rp_id.as_slice());
        Ok(Self {
            rp_id_info: RpIdInformation::new(data.rp_id.as_slice(), rp_id_hash),
            public_key: CompressedP256PublicKey::new(&data.public_key),
            // Set to 0 since we're initializing the account
            counter: 0,
            client_data_json_reconstruction_params: data.client_data_json_reconstruction_params,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::signatures::AuthType;

    use super::*;

    #[test]
    fn test_try_from_p256_raw_initialization_data() {
        let data = P256RawInitializationData {
            rp_id: SmallVec::try_from(b"example.com".to_vec()).unwrap(),
            public_key: [0u8; 33],
            client_data_json_reconstruction_params: ClientDataJsonReconstructionParams::new(
                AuthType::Create,
                false,
                false,
                false,
                None,
            ),
        };
        assert!(P256ParsedInitializationData::try_from(data).is_ok());
    }

    #[test]
    fn test_try_from_p256_raw_initialization_data_with_quotes() {
        let data = P256RawInitializationData {
            rp_id: SmallVec::try_from(b"example.com\"".to_vec()).unwrap(),
            public_key: [0u8; 33],
            client_data_json_reconstruction_params: ClientDataJsonReconstructionParams::new(
                AuthType::Create,
                false,
                false,
                false,
                None,
            ),
        };
        let result = P256ParsedInitializationData::try_from(data);

        let expected_error_code: u32 =
            ExternalSignatureProgramError::P256RelyingPartIncludeQuotes.into();
        assert!(
            matches!(result, Err(ProgramError::Custom(error_code)) if error_code == expected_error_code)
        );
    }
}
