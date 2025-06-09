use base64::{engine::general_purpose, Engine};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    instruction::{Seed, Signer},
    log::sol_log,
    program_error::ProgramError,
    pubkey::{try_find_program_address, Pubkey},
    seeds,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
};

use crate::{
    errors::ExternalSignatureProgramError,
    signatures::{
        reconstruct_client_data_json, AuthDataParser, ClientDataJsonReconstructionParams,
    },
    state::{
        AccountHeader, AccountSeeds, AccountSeedsTrait, ExternallySignedAccountData, SessionKey, SignatureScheme, SESSION_KEY_EXPIRATION_LIMIT
    },
    utils::{hash, PrecompileParser, Secp256r1Precompile, SmallVec, HASH_LENGTH},
};

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256RawInitializationData {
    pub rp_id: SmallVec<u8, u8>,
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
    pub session_key: Option<SessionKey>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
#[repr(C)]
pub struct P256ParsedInitializationData {
    pub rp_id_info: RpIdInformation,
    pub public_key: CompressedP256PublicKey,
    pub counter: u64,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
    pub session_key: SessionKey,
}

impl From<P256RawInitializationData> for P256ParsedInitializationData {
    fn from(data: P256RawInitializationData) -> Self {
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

pub struct P256DeriveAccountArgs {
    pub public_key: [u8; 33],
}

impl<'a> From<&'a P256ParsedInitializationData> for P256DeriveAccountArgs {
    fn from(data: &'a P256ParsedInitializationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

impl<'a> From<&'a P256ParsedVerificationData> for P256DeriveAccountArgs {
    fn from(data: &'a P256ParsedVerificationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod)]
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
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod)]
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

impl ExternallySignedAccountData for P256WebauthnAccountData {
    type AccountSeeds = AccountSeeds;
    type DeriveAccountArgs = P256DeriveAccountArgs;
    type RawInitializationData = P256RawInitializationData;
    type RawVerificationData = P256RawVerificationData;
    type ParsedInitializationData = P256ParsedInitializationData;
    type ParsedVerificationData = P256ParsedVerificationData;

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
        if args.session_key.expiration
            > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
        {
            return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
        }

        self.rp_id_info = args.rp_id_info;
        self.public_key = args.public_key;
        self.counter = args.counter;
        self.session_key = args.session_key;

        Ok(())
    }

    fn derive_account(args: Self::DeriveAccountArgs) -> Result<Self::AccountSeeds, ProgramError> {
        let public_key_hash = hash(&args.public_key);
        let (derived_key, bump) =
            try_find_program_address(&[b"passkey", &public_key_hash], &crate::ID).unwrap();

        Ok(AccountSeeds {
            key: derived_key,
            bump,
            seed_passkey: b"passkey",
            seed_public_key_hash: public_key_hash,
        })
    }

    fn derive_existing_account(&self) -> Result<Self::AccountSeeds, ProgramError> {
        let seeds = Self::derive_account(Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        })?;

        Ok(seeds)
    }

    fn check_account(
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
            self.counter = counter as u64;
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

    fn is_valid_session_key(&self, signer: &Pubkey) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        if self.session_key.key != *signer {
            return Err(ExternalSignatureProgramError::InvalidSessionKey.into());
        }
        if self.session_key.expiration < clock.unix_timestamp as u64 {
            return Err(ExternalSignatureProgramError::SessionKeyExpired.into());
        }
        sol_log(format!("Session Key Expiration: {:?}", self.session_key.expiration).as_str());
        sol_log(format!("Clock Timestamp: {:?}", clock.unix_timestamp).as_str());
        Ok(())
    }

    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        if session_key.expiration
            > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
        {
            return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
        }

        self.session_key = session_key;

        Ok(())
    }
}
