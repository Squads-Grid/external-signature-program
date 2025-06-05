use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    sysvars::instructions::Instructions,
    ProgramResult,
};

use crate::{
    checks::nonce::{validate_nonce, TruncatedSlot},
    errors::ExternalSignatureProgramError,
    signatures::SignatureScheme,
    state::{
        ExternallyOwnedAccount, ExternallyOwnedAccountData, P256WebauthnAccountData, SessionKey,
    },
    utils::{hash, SlotHashes, SmallVec},
};

pub struct RefreshSessionKeyAccounts<'a> {
    // [MUT]
    pub external_account: &'a AccountInfo,
    pub instructions_sysvar: &'a AccountInfo,
    pub nonce_signer: &'a AccountInfo,
    pub slothashes_sysvar: &'a AccountInfo,
}

pub struct RefreshSessionKeyContext<'a, T: ExternallyOwnedAccountData> {
    pub external_account: ExternallyOwnedAccount<'a, T>,
    pub instructions_sysvar: Instructions<Ref<'a, [u8]>>,
    pub signature_scheme_specific_verification_data: T::ParsedVerificationData,
    pub session_key: SessionKey,
    pub slothash: [u8; 32],
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct RefreshSessionKeyArgs {
    pub slothash: TruncatedSlot,
    pub signature_scheme: u8,
    pub verification_data: SmallVec<u8, u8>,
    pub session_key: SessionKey,
}

impl<'a, T: ExternallyOwnedAccountData> RefreshSessionKeyContext<'a, T> {
    pub fn load(
        account_infos: &'a [AccountInfo],
        args: &'a RefreshSessionKeyArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (external_account, instructions_sysvar, nonce_signer, slothashes_sysvar, _remaining) =
            if let [external_account, instructions_sysvar, nonce_signer, slothashes_sysvar, remaining @ ..] =
                account_infos
            {
                (
                    external_account,
                    instructions_sysvar,
                    nonce_signer,
                    slothashes_sysvar,
                    remaining,
                )
            } else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };

        let externally_owned_account = ExternallyOwnedAccount::<T>::new(external_account)?;
        let verification_args =
            T::RawVerificationData::try_from_slice(&args.verification_data.as_slice())
                .map_err(|_| ExternalSignatureProgramError::InvalidExtraVerificationDataArgs)?;
        let parsed_verification_data = T::ParsedVerificationData::from(verification_args);
        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;
        let nonce_data = validate_nonce(slothashes_sysvar, &args.slothash, nonce_signer)?;

        externally_owned_account.check_account(&parsed_verification_data)?;

        Ok(Box::new(Self {
            external_account: externally_owned_account,
            instructions_sysvar,
            signature_scheme_specific_verification_data: parsed_verification_data,
            session_key: args.session_key,
            slothash: nonce_data.slothash,
        }))
    }

    pub fn get_refresh_session_key_payload_hash(&self) -> [u8; 32] {
        let mut refresh_session_key_payload: Vec<u8> = Vec::with_capacity(104);
        refresh_session_key_payload.extend_from_slice(self.slothash.as_slice());
        refresh_session_key_payload.extend_from_slice(self.external_account.key().as_ref());

        self.session_key
            .serialize(&mut refresh_session_key_payload)
            .unwrap();
        hash(&refresh_session_key_payload)
    }
}

pub fn process_refresh_session_key(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let args =
        RefreshSessionKeyArgs::try_from_slice(data).map_err(|_| ProgramError::InvalidArgument)?;
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    let mut refresh_session_key_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            RefreshSessionKeyContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

    let signature_specific_refresh_session_key_payload =
        refresh_session_key_context.get_refresh_session_key_payload_hash();

    refresh_session_key_context
        .external_account
        .verify_payload(
            &refresh_session_key_context.instructions_sysvar,
            &refresh_session_key_context.signature_scheme_specific_verification_data,
            &signature_specific_refresh_session_key_payload,
        )?;

    refresh_session_key_context
        .external_account
        .update_session_key(args.session_key)?;

    Ok(())
}
