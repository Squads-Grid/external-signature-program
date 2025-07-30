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
        check_account_uninitialized, hash,
        nonce::{validate_nonce, TruncatedSlot},
        SlotHashes, SmallVec,
    },
};

// Raw arguments for initialization instruction data
#[derive(BorshDeserialize, BorshSerialize)]
pub struct InitializeAccountArgs {
    pub slothash: TruncatedSlot,
    pub signature_scheme: u8,
    pub initialization_data: SmallVec<u8, u8>,
    pub session_key: Option<SessionKey>,
}
// Sanitized and checked accounts for initialization
pub struct InitializeAccounts<'a, T: ExternallySignedAccountData> {
    // [MUT]
    pub externally_signed_account: ExternallySignedAccount<'a, T>,
    // [SIGNER, MUT]
    pub rent_payer: &'a AccountInfo,
    pub instructions_sysvar: Instructions<Ref<'a, [u8]>>,
    pub system_program: &'a AccountInfo,
}

// Sanitized and checked context for initialization
pub struct InitializeExternalAccountContext<'a, T: ExternallySignedAccountData> {
    pub slothash: [u8; 32],
    pub accounts: InitializeAccounts<'a, T>,
    pub externally_signed_account_seeds: T::AccountSeeds,
    pub signature_scheme_specific_initialization_data: T::ParsedInitializationData,
    pub session_key: Option<SessionKey>,
}

impl<'a, T: ExternallySignedAccountData> InitializeExternalAccountContext<'a, T> {
    // Sanitizes, checks and loads the context from the account infos and args
    pub fn load(
        account_infos: &'a [AccountInfo],
        args: &'a InitializeAccountArgs,
    ) -> Result<Self, ProgramError> {
        let (
            externally_signed_account,
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

        // Check that the account is uninitialized
        check_account_uninitialized(externally_signed_account)?;

        // Load and check the relevantaccounts
        let externally_signed_account =
            ExternallySignedAccount::<T>::load(externally_signed_account)?;
        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;

        assert_eq!(system_program.key(), &pinocchio_system::ID);

        // Validate the nonce
        let nonce_data = validate_nonce(slothashes_sysvar, &args.slothash, rent_payer)?;

        // Parse the initialization data
        let raw_initialization_data =
            T::RawInitializationData::try_from_slice(&args.initialization_data.as_slice())
                .map_err(|_| ProgramError::InvalidArgument)?;
        let parsed_initialization_data =
            T::ParsedInitializationData::try_from(raw_initialization_data)?;

        // Derive the account seeds
        let derive_args = T::DeriveAccountArgs::from(&parsed_initialization_data);
        let externally_signed_account_seeds = T::derive_account(derive_args)?;

        // Check that the externally signed account matches the derived account seeds
        if externally_signed_account
            .key()
            .ne(externally_signed_account_seeds.key())
        {
            return Err(ProgramError::InvalidAccountOwner);
        }

        Ok(Self {
            accounts: InitializeAccounts {
                externally_signed_account,
                rent_payer,
                instructions_sysvar,
                system_program,
            },
            externally_signed_account_seeds,
            signature_scheme_specific_initialization_data: parsed_initialization_data,
            slothash: nonce_data.slothash,
            session_key: args.session_key,
        })
    }

    // Creates and allocates the externally signed account
    pub fn create_and_allocate_externally_signed_account(&mut self) -> Result<(), ProgramError> {
        // Get the space required for the account
        let space = T::size();

        // Get the required lamports for the account
        let required_lamports = Rent::get()?.minimum_balance(space);

        // Create the signer seeds
        let seeds = self.externally_signed_account_seeds.seeds();
        let signer_seeds = seeds.iter().map(|s| Seed::from(*s)).collect::<Vec<Seed>>();
        let signer = [Signer::from(signer_seeds.as_slice())];

        Transfer {
            from: self.accounts.rent_payer,
            to: self.accounts.externally_signed_account.account_info,
            lamports: required_lamports,
        }
        .invoke()?;
        Allocate {
            account: self.accounts.externally_signed_account.account_info,
            space: space as u64,
        }
        .invoke_signed(&signer)?;
        Assign {
            account: self.accounts.externally_signed_account.account_info,
            owner: &crate::ID,
        }
        .invoke_signed(&signer)?;

        // Reload the account to ensure data is updated
        self.accounts.externally_signed_account.reload()?;

        Ok(())
    }

    // Creates the initialization payload hash
    fn get_initialization_payload_hash<'b>(
        &self,
        signature_specific_initialization_payload: &'b [u8],
        session_key: Option<&SessionKey>,
    ) -> [u8; 32] {
        // Will only allocate again if session key is present
        let mut payload_bytes =
            Vec::with_capacity(signature_specific_initialization_payload.len() + 32 + 32);

        // Build the expected challenge payload and hash it
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

// Processes the initialize external account instruction
pub fn process_initialize_external_account(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Parse the initialization args
    let initialization_data =
        InitializeAccountArgs::try_from_slice(data).map_err(|_| ProgramError::InvalidArgument)?;

    // Parse the signature scheme
    let signature_scheme =
        SignatureScheme::try_from_primitive(initialization_data.signature_scheme)
            .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    // Load the initialization context based on the signature scheme
    let mut initialization_context =
        match signature_scheme {
            SignatureScheme::P256Webauthn => InitializeExternalAccountContext::<
                P256WebauthnAccountData,
            >::load(accounts, &initialization_data)?,
        };

    // Get the signature specific initialization payload
    let signature_specific_initialization_payload = initialization_context
        .accounts
        .externally_signed_account
        .get_initialization_payload();

    // Get the initialization payload hash
    let initialization_payload_hash = initialization_context.get_initialization_payload_hash(
        signature_specific_initialization_payload,
        initialization_context.session_key.as_ref(),
    );

    // Create and allocate the externally signed account
    initialization_context.create_and_allocate_externally_signed_account()?;

    // Initialize the externally signed account
    let mut externally_owned_account = initialization_context.accounts.externally_signed_account;

    externally_owned_account.initialize_account(
        &initialization_context.signature_scheme_specific_initialization_data,
        initialization_context.session_key,
    )?;

    // Verify the initialization payload (since we depend on the contents of the
    // account to exist, we do this step last)
    externally_owned_account.verify_initialization_payload(
        &initialization_context.accounts.instructions_sysvar,
        &initialization_context.signature_scheme_specific_initialization_data,
        &initialization_payload_hash,
    )?;

    Ok(())
}
