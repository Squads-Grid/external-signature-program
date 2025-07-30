use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::try_find_program_address,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{
        ExternallySignedAccountData, SessionKey, SignatureScheme, SESSION_KEY_EXPIRATION_LIMIT,
    },
    utils::{
        hash,
        signatures::{reconstruct_client_data_json, AuthDataParser},
        PrecompileParser, Secp256r1Precompile,
    },
};

use super::{
    AccountSeeds, P256DeriveAccountArgs, P256ParsedInitializationData, P256ParsedVerificationData,
    P256RawInitializationData, P256RawVerificationData, P256WebauthnAccountData,
};

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
        session_key: Option<SessionKey>,
    ) -> Result<(), ProgramError> {
        // Set fields from initialization data
        self.rp_id_info = args.rp_id_info;
        self.public_key = args.public_key;
        self.counter = args.counter;

        // Set session key if provided
        if let Some(session_key) = session_key {
            // Check that the session key is not above the expiration limit
            if session_key.expiration
                > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
            {
                return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
            }

            self.session_key = session_key;
        }

        Ok(())
    }

    /// Derives a new account from the public key
    fn derive_account(args: Self::DeriveAccountArgs) -> Result<Self::AccountSeeds, ProgramError> {
        // Since the limit for seeds is 32 bytes per seed, we hash the public key
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

    /// Derive the account seeds from the account data
    fn derive_existing_account(&self) -> Result<Self::AccountSeeds, ProgramError> {
        let seeds = Self::derive_account(Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        })?;

        Ok(seeds)
    }

    /// Check the account based on the parsed verification data
    fn check_account(
        &self,
        account_info: &AccountInfo,
        _args: &Self::ParsedVerificationData,
    ) -> Result<Self::AccountSeeds, ProgramError> {
        // Since the counter needs to be updated, we always need to check that
        // the account is writable
        if !account_info.is_writable() {
            return Err(ExternalSignatureProgramError::P256AccountNotWritable.into());
        }
        let derive_args = Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        };
        // Check that the account matches the seeds
        let account_seeds = Self::derive_account(derive_args)?;
        if account_seeds.key.ne(account_info.key()) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        Ok(account_seeds)
    }

    /// Verifies an instruction execution payload
    fn verify_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        extra_verification_data: &Self::ParsedVerificationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        // Load the ix at index 0
        let precompile_instruction = instructions_sysvar_account.load_instruction_at(0)?;

        // Initialize the precompile parser
        let parser = PrecompileParser::<Secp256r1Precompile>::new(
            &precompile_instruction,
            &instructions_sysvar_account,
        )?;

        // Check that there is only one signature
        let num_signatures = parser.num_signatures();
        if num_signatures != 1 {
            return Err(ExternalSignatureProgramError::InvalidNumPrecompileSignatures.into());
        }

        // Get the 0th signature payload
        let signature_payload = parser.get_signature_payload(0)?;

        // Check the payloads pubkey matches the account data
        let payload_pubkey = signature_payload.public_key;
        if payload_pubkey != self.public_key.to_bytes() {
            return Err(ExternalSignatureProgramError::P256PublicKeyMismatch.into());
        }

        // Split the signature payload into auth data and client data hash
        let (auth_data, client_data_hash) = signature_payload
            .message
            .split_at(signature_payload.message.len() - 32);
        // Create the auth data parser and get the RP ID hash
        let auth_data_parser = AuthDataParser::new(auth_data);

        // Check that the user is present
        if !auth_data_parser.is_user_present() {
            return Err(ExternalSignatureProgramError::P256UserNotPresent.into());
        }

        // Check that the user is verified (Not sure whether we want to enforce
        // this at all times yet, as it adds some extra friction with yubikeys)
        // if !auth_data_parser.is_user_verified() {
        //     return Err(ExternalSignatureProgramError::UserNotVerified.into());
        // }

        // Compare the RP ID hash from the auth data with the RP ID hash from the account data
        let rp_id_hash = auth_data_parser.rp_id_hash();
        let rp_id: &[u8] = &self.rp_id_info.rp_id[..(self.rp_id_info.rp_id_len as usize)];
        if self.rp_id_info.rp_id_hash.ne(&rp_id_hash) {
            return Err(ExternalSignatureProgramError::P256RelyingPartyMismatch.into());
        }

        // Reconstruct the client data JSON
        let reconstructed_client_data = reconstruct_client_data_json(
            &extra_verification_data.client_data_json_reconstruction_params,
            &rp_id,
            &payload,
        );
        let reconstructed_client_data_hash = hash(&reconstructed_client_data);

        // Compare the reconstructed client data hash with the client data hash
        if reconstructed_client_data_hash != client_data_hash {
            return Err(ExternalSignatureProgramError::P256ClientDataHashMismatch.into());
        }

        // Get the counter from the auth data
        let counter = auth_data_parser.get_counter();

        // Update the counter if it is greater than the current counter
        if counter != 0 {
            // Check that the counter is greater than the current counter
            assert!(counter as u64 > self.counter);
            self.counter = counter as u64;
        }
        Ok(())
    }

    /// Verifies an initialization payload
    fn verify_initialization_payload<'a>(
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

    /// Validates a session key
    fn is_valid_session_key(&self, signer: &AccountInfo) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        // Check that the signer is a signer
        if !signer.is_signer() {
            return Err(ExternalSignatureProgramError::SessionSignerNotASigner.into());
        }
        // Check that the signer is the session key
        if self.session_key.key != *signer.key() {
            return Err(ExternalSignatureProgramError::InvalidSessionKey.into());
        }
        // Check that the session key is not expired
        if self.session_key.expiration < clock.unix_timestamp as u64 {
            return Err(ExternalSignatureProgramError::SessionKeyExpired.into());
        }
        Ok(())
    }

    /// Updates the session key
    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        // Check that the session key is not above the expiration limit
        if session_key.expiration
            > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
        {
            return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
        }

        self.session_key = session_key;

        Ok(())
    }
}
