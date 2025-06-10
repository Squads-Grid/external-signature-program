use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{instructions::Instructions, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{
        AccountSeedsTrait, ExternallySignedAccount, ExternallySignedAccountData,
        P256WebauthnAccountData, SessionKey, SignatureScheme,
    },
    utils::{
        hash,
        nonce::{validate_nonce, TruncatedSlot},
        SlotHashes, SmallVec,
    },
};

pub struct InitializeAccounts<'a, T: ExternallySignedAccountData> {
    // [MUT]
    pub external_account: ExternallySignedAccount<'a, T>,
    // [SIGNER]
    pub rent_payer: &'a AccountInfo,
    pub instructions_sysvar: Instructions<Ref<'a, [u8]>>,
    pub system_program: &'a AccountInfo,
}

pub struct InitializeExternalAccountContext<'a, T: ExternallySignedAccountData> {
    pub accounts: InitializeAccounts<'a, T>,
    pub external_account_seeds: T::AccountSeeds,
    pub signature_scheme_specific_initialization_data: T::ParsedInitializationData,
    pub slothash: [u8; 32],
    pub session_key: Option<SessionKey>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct InitializeAccountArgs {
    pub slothash: TruncatedSlot,
    pub signature_scheme: u8,
    pub initialization_data: SmallVec<u8, u8>,
    pub session_key: Option<SessionKey>,
}

impl<'a, T: ExternallySignedAccountData> InitializeExternalAccountContext<'a, T> {
    pub fn load(
        account_infos: &'a [AccountInfo],
        args: &'a InitializeAccountArgs,
    ) -> Result<Self, ProgramError> {
        let (
            external_account,
            rent_payer,
            instructions_sysvar,
            slothashes_sysvar,
            system_program,
            _remaining,
        ) = if let [external_account, rent_payer, instructions_sysvar, slothashes_sysvar, system_program, remaining @ ..] =
            account_infos
        {
            (
                external_account,
                rent_payer,
                instructions_sysvar,
                slothashes_sysvar,
                system_program,
                remaining,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Only checking pre-initialization, so the reference doesnt need
        // maintain validity
        unsafe {
            if external_account.owner().ne(&pinocchio_system::ID) {
                return Err(ProgramError::InvalidAccountOwner);
            }
        }

        if external_account.data_len().ne(&0) {
            return Err(ProgramError::InvalidAccountData);
        };

        let externally_signed_account = ExternallySignedAccount::<T>::new(external_account)?;
        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;
        let nonce_data = validate_nonce(slothashes_sysvar, &args.slothash, rent_payer)?;
        let raw_initialization_data =
            T::RawInitializationData::try_from_slice(&args.initialization_data.as_slice())
                .map_err(|_| ProgramError::InvalidArgument)?;
        let parsed_initialization_data = T::ParsedInitializationData::from(raw_initialization_data);
        let derive_args = T::DeriveAccountArgs::from(&parsed_initialization_data);
        let external_account_seeds = T::derive_account(derive_args)?;
        if externally_signed_account
            .key()
            .ne(external_account_seeds.key())
        {
            return Err(ProgramError::InvalidAccountOwner);
        }

        Ok(Self {
            accounts: InitializeAccounts {
                external_account: externally_signed_account,
                rent_payer,
                instructions_sysvar,
                system_program,
            },
            external_account_seeds,
            signature_scheme_specific_initialization_data: parsed_initialization_data,
            slothash: nonce_data.slothash,
            session_key: args.session_key,
        })
    }

    pub fn create_and_allocate_account(&mut self) -> Result<(), ProgramError> {
        let space = T::size();
        let required_lamports = Rent::get()?.minimum_balance(space);

        let seeds = self.external_account_seeds.seeds();
        let signer_seeds = seeds.iter().map(|s| Seed::from(*s)).collect::<Vec<Seed>>();
        let signer = [Signer::from(signer_seeds.as_slice())];

        Transfer {
            from: self.accounts.rent_payer,
            to: self.accounts.external_account.account_info,
            lamports: required_lamports,
        }
        .invoke()?;
        Allocate {
            account: self.accounts.external_account.account_info,
            space: space as u64,
        }
        .invoke_signed(&signer)?;
        Assign {
            account: self.accounts.external_account.account_info,
            owner: &crate::ID,
        }
        .invoke_signed(&signer)?;

        self.accounts.external_account.reload()?;

        Ok(())
    }

    fn get_initialization_payload_hash<'b>(
        &self,
        signature_specific_initialization_payload: &'b [u8],
        session_key: Option<&SessionKey>,
    ) -> [u8; 32] {
        let mut payload_bytes =
            Vec::with_capacity(signature_specific_initialization_payload.len() + 32 + 32);
        payload_bytes.extend_from_slice(&self.slothash);
        payload_bytes.extend_from_slice(self.accounts.rent_payer.key());
        payload_bytes.extend_from_slice(&signature_specific_initialization_payload);
        if let Some(session_key) = session_key {
            payload_bytes.extend_from_slice(&session_key.key);
            payload_bytes.extend_from_slice(&session_key.expiration.to_le_bytes());
        }
        hash(&payload_bytes)
    }
}

pub fn process_initialize_external_account(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let initialization_data =
        InitializeAccountArgs::try_from_slice(data).map_err(|_| ProgramError::InvalidArgument)?;
    let signature_scheme =
        SignatureScheme::try_from_primitive(initialization_data.signature_scheme)
            .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    let mut initialization_context =
        match signature_scheme {
            SignatureScheme::P256Webauthn => InitializeExternalAccountContext::<
                P256WebauthnAccountData,
            >::load(accounts, &initialization_data)?,
        };

    let signature_specific_initialization_payload = initialization_context
        .accounts
        .external_account
        .get_initialization_payload();

    let initialization_payload_hash = initialization_context.get_initialization_payload_hash(
        signature_specific_initialization_payload,
        initialization_context.session_key.as_ref(),
    );

    initialization_context.create_and_allocate_account()?;

    let mut externally_owned_account = initialization_context.accounts.external_account;

    externally_owned_account.initialize_account(
        &initialization_context.signature_scheme_specific_initialization_data,
        initialization_context.session_key,
    )?;

    externally_owned_account.verfiy_initialization_payload(
        &initialization_context.accounts.instructions_sysvar,
        &initialization_context.signature_scheme_specific_initialization_data,
        &initialization_payload_hash,
    )?;

    Ok(())
}
