use base64::{engine::general_purpose, Engine};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    log::sol_log,
    program_error::ProgramError,
    pubkey::{try_find_program_address, Pubkey},
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
};

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
        self.rp_id_info = args.rp_id_info;
        self.public_key = args.public_key;
        self.counter = args.counter;
        self.session_key = args.session_key;

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

    fn is_valid_session_key(&self, signer: &Pubkey) -> Result<bool, ProgramError> {
        let clock = Clock::get()?;
        Ok(self.session_key.key == *signer && self.session_key.expiration > clock.slot)
    }

    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        self.session_key = session_key;
        Ok(())
    }
}