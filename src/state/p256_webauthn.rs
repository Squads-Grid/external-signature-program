use base64::{engine::general_purpose, Engine};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    instruction::{Seed, Signer},
    log::sol_log,
    msg,
    program_error::ProgramError,
    pubkey::{try_find_program_address, Pubkey},
    seeds,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError, instructions::refresh_session_key::RefreshSessionKeyArgs, signatures::{
        reconstruct_client_data_json, AuthDataParser, AuthType, ClientDataJsonReconstructionParams,
        SignatureScheme,
    }, utils::{hash, hashv, PrecompileParser, Secp256r1Precompile, SmallVec, HASH_LENGTH}
};

use super::{AccountHeader, AccountSeedsTrait, ExternallyOwnedAccountData};

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

pub struct AccountSeeds {
    pub key: Pubkey,
    pub bump: u8,
    seed_passkey: &'static [u8],
    seed_public_key_hash: [u8; 32],
}

impl AccountSeedsTrait for AccountSeeds {
    fn key(&self) -> &Pubkey {
        &self.key
    }
    fn bump(&self) -> u8 {
        self.bump
    }
    fn seeds(&self) -> Vec<&[u8]> {
        vec![
            self.seed_passkey,
            &self.seed_public_key_hash,
            core::slice::from_ref(&self.bump),
        ]
    }
}

impl ExternallyOwnedAccountData for P256WebauthnAccountData {
    type AccountSeeds = AccountSeeds;
    type RawInitializationData = P256WebauthnRawInitializationData;
    type ParsedInitializationData = P256WebauthnParsedInitializationData;
    type RawVerificationData = P256WebauthnRawVerificationData;
    type ParsedVerificationData = P256WebauthnParsedVerificationData;
    type DeriveAccountArgs = P256WebauthnDeriveAccountArgs;

    fn version() -> u8 {
        1
    }

    fn scheme() -> u8 {
        SignatureScheme::P256Webauthn as u8
    }

    fn size() -> usize {
        core::mem::size_of::<P256WebauthnAccountData>()
    }

    fn get_initialization_payload() -> &'static [u8] {
        b"initialize_passkey"
    }

    fn initialize_account(
        &mut self,
        args: &Self::ParsedInitializationData,
    ) -> Result<(), ProgramError> {
        self.set_rp_id_info(args.rp_id_info);
        self.set_public_key(args.public_key);
        self.set_counter(args.counter);
        self.set_session_key(args.session_key);
        Ok(())
    }

    fn derive_account<'a>(args: Self::DeriveAccountArgs) -> Result<AccountSeeds, ProgramError> {
        let public_key_hash = hash(&args.public_key);
        let seeds: [&[u8]; 2] = [b"passkey", &public_key_hash];
        let (derived_key, bump) = try_find_program_address(&seeds, &crate::ID).unwrap();
        Ok(AccountSeeds {
            key: derived_key,
            bump,
            seed_passkey: b"passkey",
            seed_public_key_hash: public_key_hash,
        })
    }

    fn check_account<'a>(
        &self,
        account_info: &AccountInfo,
        _args: &Self::ParsedVerificationData,
    ) -> Result<Self::AccountSeeds, ProgramError> {
        if !account_info.is_writable() {
            return Err(ExternalSignatureProgramError::AccountNotWritable.into());
        }
        let derive_args = Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        };
        let account_seeds = Self::derive_account(derive_args)?;
        if account_seeds.key.ne(account_info.key()) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        Ok(account_seeds)
    }

    fn verify_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        extra_verification_data: &Self::ParsedVerificationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let precompile_instruction = instructions_sysvar_account.load_instruction_at(0)?;
        let parser = PrecompileParser::<Secp256r1Precompile>::new(
            &precompile_instruction,
            &instructions_sysvar_account,
        )?;
        let num_signatures = parser.num_signatures();
        if num_signatures != 1 {
            return Err(ExternalSignatureProgramError::InvalidNumPrecompileSignatures.into());
        }
        let signature_payload = parser.get_signature_payload_at(0)?;

        let (auth_data, client_data_hash) = signature_payload
            .message
            .split_at(signature_payload.message.len() - 32);
        let auth_data_parser = AuthDataParser::new(auth_data);
        let rp_id_hash = auth_data_parser.rp_id_hash();

        let rp_id: &[u8] = &self.rp_id_info.rp_id[..(self.rp_id_info.rp_id_len as usize)];

        if self.rp_id_info.rp_id_hash.ne(&rp_id_hash) {
            return Err(ExternalSignatureProgramError::RelyingPartyMismatch.into());
        }
        let reconstructed_client_data = reconstruct_client_data_json(
            &extra_verification_data.client_data_json_reconstruction_params,
            &rp_id,
            &payload,
        );
        let base_64_payload = general_purpose::URL_SAFE_NO_PAD.encode(&payload);
        let base_64_reconstructed_client_data =
            general_purpose::URL_SAFE_NO_PAD.encode(&reconstructed_client_data);
        sol_log(&base_64_payload);
        sol_log(&base_64_reconstructed_client_data);

        let reconstructed_client_data_hash = hash(&reconstructed_client_data);

        if reconstructed_client_data_hash != client_data_hash {
            return Err(ExternalSignatureProgramError::ClientDataHashMismatch.into());
        }

        let counter = auth_data_parser.get_counter();

        if counter != 0 {
            assert!(counter as u64 > self.counter);
            self.set_counter(counter as u64);
        }
        Ok(())
    }

    fn verfiy_initialization_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        initialization_data: &Self::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let verification_args = Self::ParsedVerificationData {
            client_data_json_reconstruction_params: initialization_data
                .client_data_json_reconstruction_params,
            public_key: initialization_data.public_key,
        };
        self.verify_payload(instructions_sysvar_account, &verification_args, payload)?;
        Ok(())
    }

    fn is_valid_session_key(&self, signer: &Pubkey) -> Result<bool, ProgramError> {
        let clock = Clock::get()?;
        Ok(self.session_key.key == *signer && self.session_key.expiration > clock.slot)
    }

    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        self.session_key = session_key;
        Ok(())
    }
}

/// P-256 (secp256r1) account data
#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct P256WebauthnAccountData {
    /// Exists here purely for alignment
    _header: AccountHeader,

    /// RP ID information
    pub rp_id_info: RpIdInformation,

    /// P-256 public key
    pub public_key: CompressedP256PublicKey,
 
    /// Padding to ensure alignment
    pub padding: [u8; 2],

    /// Session key
    pub session_key: SessionKey,

    // Webauthn signature counter (used mostly by security keys)
    pub counter: u64,
}

impl P256WebauthnAccountData {
    pub fn set_rp_id_info(&mut self, rp_id: RpIdInformation) {
        self.rp_id_info = rp_id;
    }
    pub fn set_public_key(&mut self, public_key: CompressedP256PublicKey) {
        self.public_key = public_key;
    }

    pub fn set_counter(&mut self, counter: u64) {
        self.counter = counter;
    }

    pub fn set_session_key(&mut self, session_key: SessionKey) {
        self.session_key = session_key;
    }
}

#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct CompressedP256PublicKey {
    pub x: [u8; 32],
    pub y_parity: u8,
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
#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct RpIdInformation {
    pub rp_id_len: u8,
    pub rp_id: [u8; 32],
    pub rp_id_hash: [u8; 32],
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
