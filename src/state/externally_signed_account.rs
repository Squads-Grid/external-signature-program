use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{try_find_program_address, Pubkey, PUBKEY_BYTES},
    seeds,
    sysvars::instructions::Instructions,
};

use crate::errors::ExternalSignatureProgramError;

pub const SESSION_KEY_EXPIRATION_LIMIT: u64 = 3 * 30 * 24 * 60 * 60; // 3 months in seconds

/// Version and type header for all account data
#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct AccountHeader {
    /// Version number for forward compatibility
    pub version: u8,

    /// Signature scheme identifier
    pub scheme: u8,

    pub reserved: [u8; 2],
}

impl AccountHeader {
    pub fn size() -> usize {
        core::mem::size_of::<AccountHeader>()
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn scheme(&self) -> u8 {
        self.scheme
    }
    pub fn set<T: ExternallySignedAccountData>(&mut self) {
        self.version = T::version();
        self.scheme = T::scheme();
    }
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod, Default)]
#[repr(C)]
pub struct SessionKey {
    pub key: [u8; PUBKEY_BYTES],
    pub expiration: u64,
}

#[derive(TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum SignatureScheme {
    P256Webauthn = 0,
    // more schemes here
}

#[derive(TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum SignerExecutionScheme {
    /// Uses the derived execution account as the signer (legacy/default behavior)
    /// Useful for system operations like paying rent
    ExecutionAccount = 0,

    /// Uses the externally signed account directly as the signer
    /// More efficient for smart account operations
    ExternalAccount = 1,
}

pub trait AccountSeedsTrait {
    fn key(&self) -> &Pubkey;
    fn bump(&self) -> u8;
    fn seeds(&self) -> Vec<&[u8]>;
    fn seeds_owned(&self) -> [Vec<u8>; 2];
}

pub struct AccountSeeds {
    pub key: Pubkey,
    pub bump: u8,
    pub(crate) seed_passkey: &'static [u8],
    pub(crate) seed_public_key_hash: [u8; 32],
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
    fn seeds_owned(&self) -> [Vec<u8>; 2] {
        let seeds = [self.seed_passkey, &self.seed_public_key_hash];
        seeds.map(|s| s.to_vec())
    }
}

pub trait ExternallySignedAccountData: Pod + Zeroable + Clone + Copy {
    type AccountSeeds: AccountSeedsTrait;
    type DeriveAccountArgs: for<'a> From<&'a Self::ParsedVerificationData>
        + for<'a> From<&'a Self::ParsedInitializationData>;

    type RawInitializationData: BorshDeserialize;
    type RawVerificationData: BorshDeserialize;
    type ParsedInitializationData: From<Self::RawInitializationData>;
    type ParsedVerificationData: From<Self::RawVerificationData>;

    fn get_initialization_payload() -> &'static [u8];
    fn initialize_account(
        &mut self,
        args: &Self::ParsedInitializationData,
    ) -> Result<(), ProgramError>;
    fn check_account<'a>(
        &self,
        account_info: &AccountInfo,
        args: &Self::ParsedVerificationData,
    ) -> Result<Self::AccountSeeds, ProgramError>;
    fn derive_account<'a>(
        args: Self::DeriveAccountArgs,
    ) -> Result<Self::AccountSeeds, ProgramError>;
    fn derive_existing_account<'a>(&self) -> Result<Self::AccountSeeds, ProgramError>;
    fn version() -> u8;
    fn scheme() -> u8;
    fn size() -> usize;
    fn seeds(&self) -> Result<([Seed; 2], u8), ProgramError>;
    fn verfiy_initialization_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        initialization_data: &Self::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError>;
    fn verify_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        extra_verification_data: &Self::ParsedVerificationData,
        payload: &[u8],
    ) -> Result<(), ProgramError>;
    fn is_valid_session_key(&self, signer: &Pubkey) -> Result<(), ProgramError>;
    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError>;
}

pub struct ExecutionAccount<'a> {
    pub key: Pubkey,
    pub bump: u8,
    pub seeds: [&'a [u8]; 2],
    pub account_info: &'a AccountInfo,
}

impl<'a> ExecutionAccount<'a> {
    pub fn to_signer_seeds(&self) -> [Seed; 3] {
        let bump_ref = core::slice::from_ref(&self.bump);
        let seeds = seeds!(self.seeds[0], self.seeds[1], bump_ref);
        seeds
    }
}

pub struct ExternallySignedAccount<'a, T: ExternallySignedAccountData> {
    phantom: PhantomData<T>,
    pub account_info: &'a AccountInfo,
    data: &'a mut [u8],
}

impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    pub fn new(account_info: &'a AccountInfo) -> Result<Self, ProgramError> {
        let mut data = account_info.try_borrow_mut_data()?;
        let data_ptr = data.as_mut_ptr(); // Get a raw pointer to the data
        let data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(data_ptr, data.len()) };
        Ok(Self {
            phantom: PhantomData,
            account_info,
            data: data_slice,
        })
    }

    pub fn reload(&mut self) -> Result<(), ProgramError> {
        let mut reloaded_data = self.account_info.try_borrow_mut_data()?;
        let reloaded_data_ptr = reloaded_data.as_mut_ptr();
        let reloaded_data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(reloaded_data_ptr, reloaded_data.len()) };
        self.data = reloaded_data_slice;
        Ok(())
    }

    pub fn initialize_header(&mut self) {
        let header =
            bytemuck::from_bytes_mut::<AccountHeader>(&mut self.data[0..AccountHeader::size()]);
        header.set::<T>();
    }

    pub fn initialize_account(
        &mut self,
        args: &T::ParsedInitializationData,
    ) -> Result<(), ProgramError> {
        self.initialize_header();
        let data = self.data()?;
        T::initialize_account(data, &args)?;
        Ok(())
    }

    pub fn is_valid_session_key(&self, signer: &Pubkey) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::is_valid_session_key(data, signer)
    }

    pub fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::update_session_key(data, session_key)?;
        Ok(())
    }

    pub fn verify_payload<'b>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'b, [u8]>>,
        extra_verification_data: &T::ParsedVerificationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::verify_payload(
            data,
            instructions_sysvar_account,
            extra_verification_data,
            payload,
        )?;
        Ok(())
    }

    pub fn verfiy_initialization_payload<'b>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'b, [u8]>>,
        initialization_data: &T::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::verfiy_initialization_payload(
            data,
            instructions_sysvar_account,
            initialization_data,
            payload,
        )
    }

    pub fn key(&self) -> &Pubkey {
        self.account_info.key()
    }

    pub fn get_initialization_payload(&self) -> &'static [u8] {
        T::get_initialization_payload()
    }

    pub fn get_execution_account(
        &self,
        signer_execution_scheme: SignerExecutionScheme,
    ) -> Result<ExecutionAccount<'a>, ProgramError> {
        let (execution_account, seeds, bump): (Pubkey, [Vec<u8>; 2], u8) =
            match signer_execution_scheme {
                SignerExecutionScheme::ExternalAccount => {
                    let external_account_seeds = self.derive_existing_account()?;
                    let seeds = external_account_seeds.seeds_owned();

                    (
                        external_account_seeds.key().to_owned(),
                        seeds,
                        external_account_seeds.bump(),
                    )
                }
                SignerExecutionScheme::ExecutionAccount => {
                    let seeds = [self.account_info.key().as_ref(), b"execution_account"];
                    let (execution_account, bump) =
                        try_find_program_address(&seeds, &crate::ID).unwrap();
                    let seeds_vec = seeds.map(|s| s.to_vec());
                    let execution_account = Pubkey::from(execution_account);

                    (execution_account, seeds_vec, bump)
                }
            };

        let seed_refs: [&[u8]; 2] = [&seeds[0], &seeds[1]];

        Ok(ExecutionAccount {
            key: execution_account,
            bump,
            seeds: seed_refs,
            account_info: self.account_info,
        })
    }

    pub fn size() -> usize {
        core::mem::size_of::<T>()
    }

    pub fn header(&self) -> &mut AccountHeader {
        // Since we know ExternallyOwnedAccountMut is a mutable reference, we
        // can safely return a mutable reference to the header
        let data_ptr = self.data as *const [u8] as *mut [u8];
        unsafe {
            bytemuck::from_bytes_mut::<AccountHeader>(&mut (*data_ptr)[0..AccountHeader::size()])
        }
    }

    pub fn derive_account(args: T::DeriveAccountArgs) -> Result<T::AccountSeeds, ProgramError> {
        T::derive_account(args)
    }

    pub fn derive_existing_account(&self) -> Result<T::AccountSeeds, ProgramError> {
        let data = self.data()?;
        T::derive_existing_account(data)
    }

    pub fn check_account(
        &self,
        args: &T::ParsedVerificationData,
    ) -> Result<T::AccountSeeds, ProgramError> {
        let data = self.data()?;
        T::check_account(&data, self.account_info, args)
    }

    pub fn data(&self) -> Result<&'a mut T, ProgramError> {
        let header = self.header();

        if header.version() != T::version() || header.scheme() != T::scheme() {
            return Err(ExternalSignatureProgramError::ErrorDeserializingHeader.into());
        }
        if self.data.len() < T::size() {
            return Err(ExternalSignatureProgramError::ErrorDeserializingAccountData.into());
        }
        // Since we know ExternallyOwnedAccountMut is a mutable reference, we
        // can safely return a mutable reference to the data
        let data_ptr = self.data as *const [u8] as *mut [u8];
        unsafe {
            Ok(
                bytemuck::try_from_bytes_mut::<T>(&mut (*data_ptr)[..T::size()])
                    .map_err(|_| ExternalSignatureProgramError::ErrorDeserializingAccountData)?,
            )
        }
    }
}
