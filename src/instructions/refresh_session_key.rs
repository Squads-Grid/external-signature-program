use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{
        ExternallySignedAccount, ExternallySignedAccountData, P256WebauthnAccountData, SessionKey,
        SignatureScheme,
    },
    utils::{hash, nonce::{validate_nonce, TruncatedSlot}, NonceData, SlotHashes, SmallVec},
};

// Raw arguments for refresh session key instruction data
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RefreshSessionKeyArgs {
    pub slothash: TruncatedSlot,
    pub signature_scheme: u8,
    pub verification_data: SmallVec<u8, u8>,
    pub session_key: SessionKey,
}

// Sanitized and checked accounts for refresh session key
pub struct RefreshSessionKeyAccounts<'a, T: ExternallySignedAccountData> {
    // [MUT]
    pub externally_signed_account: ExternallySignedAccount<'a, T>,
    pub instructions_sysvar: Instructions<Ref<'a, [u8]>>,
    // [SIGNER]
    pub nonce_signer: &'a AccountInfo,
}

// Sanitized and checked context for refresh session key
pub struct RefreshSessionKeyContext<'a, T: ExternallySignedAccountData> {
    pub nonce_data: NonceData<'a>,
    pub signature_scheme_specific_verification_data: T::ParsedVerificationData,
    pub accounts: RefreshSessionKeyAccounts<'a, T>,
    pub session_key: SessionKey,
}

impl<'a, T: ExternallySignedAccountData> RefreshSessionKeyContext<'a, T> {
    // Sanitizes, checks and loads the context from the account infos and args
    pub fn load(
        account_infos: &'a [AccountInfo],
        args: &'a RefreshSessionKeyArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (
            externally_signed_account,
            instructions_sysvar,
            slothashes_sysvar,
            nonce_signer,
            _remaining,
        ) = if let [externally_signed_account, instructions_sysvar, slothashes_sysvar, nonce_signer, remaining @ ..] =
            account_infos
        {
            (
                externally_signed_account,
                instructions_sysvar,
                slothashes_sysvar,
                nonce_signer,
                remaining,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        // Parse the signature scheme specific verification data
        let verification_args =
            T::RawVerificationData::try_from_slice(&args.verification_data.as_slice())
                .map_err(|_| ExternalSignatureProgramError::InvalidExtraVerificationDataArgs)?;
        let parsed_verification_data: <T as ExternallySignedAccountData>::ParsedVerificationData = T::ParsedVerificationData::try_from(verification_args)
            .map_err(|_| ExternalSignatureProgramError::InvalidExtraVerificationDataArgs)?;

        // Load and check the relevant accounts
        let externally_signed_account =
            ExternallySignedAccount::<T>::load(externally_signed_account)?;
        externally_signed_account.check_account(&parsed_verification_data)?;
        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;

        // Validate the nonce
        let nonce_data = validate_nonce(slothashes_sysvar, &args.slothash, nonce_signer)?;

        Ok(Box::new(Self {
            nonce_data,
            signature_scheme_specific_verification_data: parsed_verification_data,
            accounts: RefreshSessionKeyAccounts {
                externally_signed_account,
                instructions_sysvar,
                nonce_signer,
            },
            session_key: args.session_key,
        }))
    }

    // Gets the refresh session key payload hash
    pub fn get_refresh_session_key_payload_hash(&self) -> [u8; 32] {
        let mut refresh_session_key_payload: Vec<u8> = Vec::with_capacity(104);
        // Nonce data
        refresh_session_key_payload.extend_from_slice(self.nonce_data.slothash.as_slice());
        refresh_session_key_payload.extend_from_slice(self.nonce_data.signer_key.as_ref());
        refresh_session_key_payload.extend_from_slice(b"refresh_session_key");

        // Session key
        self.session_key
            .serialize(&mut refresh_session_key_payload)
            .unwrap();
        hash(&refresh_session_key_payload)
    }
}

/// Processes the refresh session key instruction
pub fn process_refresh_session_key(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Parse the refresh session key args
    let args =
        RefreshSessionKeyArgs::try_from_slice(data).map_err(|_| ProgramError::InvalidArgument)?;
    // Parse the signature scheme
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    // Load the refresh session key context based on the signature scheme
    let mut refresh_session_key_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            RefreshSessionKeyContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

    // Get the refresh session key payload hash
    let signature_specific_refresh_session_key_payload =
        refresh_session_key_context.get_refresh_session_key_payload_hash();

    // Verify the refresh session key payload
    refresh_session_key_context
        .accounts
        .externally_signed_account
        .verify_payload(
            &refresh_session_key_context.accounts.instructions_sysvar,
            &refresh_session_key_context.signature_scheme_specific_verification_data,
            &signature_specific_refresh_session_key_payload,
        )?;

    // Calculate the new session key expiration
    let session_key_expiration = Clock::get()?.unix_timestamp + args.session_key.expiration as i64;
    let session_key = SessionKey {
        key: args.session_key.key,
        expiration: session_key_expiration as u64,
    };

    // Update the session key
    refresh_session_key_context
        .accounts
        .externally_signed_account
        .update_session_key(session_key)?;

    Ok(())
}
