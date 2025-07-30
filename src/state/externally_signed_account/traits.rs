use borsh::BorshDeserialize;
use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::instructions::Instructions,
};

use super::SessionKey;

/// Trait for easy access to the account seeds
pub trait AccountSeedsTrait {
    fn key(&self) -> &Pubkey;
    fn bump(&self) -> u8;
    fn seeds(&self) -> Vec<&[u8]>;
    fn seeds_owned(&self) -> [Vec<u8>; 2];
}

/// Trait for the externally signed account data
pub trait ExternallySignedAccountData: Pod + Zeroable + Clone + Copy {
    type AccountSeeds: AccountSeedsTrait;
    type DeriveAccountArgs: for<'a> From<&'a Self::ParsedVerificationData>
        + for<'a> From<&'a Self::ParsedInitializationData>;

    type RawInitializationData: BorshDeserialize;
    type RawVerificationData: BorshDeserialize;
    type ParsedInitializationData: TryFrom<Self::RawInitializationData, Error = ProgramError>;
    type ParsedVerificationData: TryFrom<Self::RawVerificationData, Error = ProgramError>;

    /// Returns the version of the account
    fn version() -> u8;
    fn scheme() -> u8;
    fn size() -> usize;

    /// Returns the signature scheme specific initialization payload
    fn get_initialization_payload() -> &'static [u8];

    /// Initializes the account
    fn initialize_account(
        &mut self,
        args: &Self::ParsedInitializationData,
        session_key: Option<SessionKey>,
    ) -> Result<(), ProgramError>;

    /// Checks the account based on the parsed verification data
    fn check_account<'a>(
        &self,
        account_info: &AccountInfo,
        args: &Self::ParsedVerificationData,
    ) -> Result<Self::AccountSeeds, ProgramError>;

    /// Derives a new account from args
    fn derive_account<'a>(
        args: Self::DeriveAccountArgs,
    ) -> Result<Self::AccountSeeds, ProgramError>;

    /// Derives an existing account from the account data
    fn derive_existing_account<'a>(&self) -> Result<Self::AccountSeeds, ProgramError>;

    /// Verifies an initialization payload
    fn verify_initialization_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        initialization_data: &Self::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError>;

    /// Verifies an instruction execution payload
    fn verify_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        extra_verification_data: &Self::ParsedVerificationData,
        payload: &[u8],
    ) -> Result<(), ProgramError>;

    /// Checks if a session key is valid
    fn is_valid_session_key(&self, signer: &AccountInfo) -> Result<(), ProgramError>;

    /// Updates the session key
    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError>;
}
