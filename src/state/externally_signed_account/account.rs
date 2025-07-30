use std::marker::PhantomData;

use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::{try_find_program_address, Pubkey},
    sysvars::instructions::Instructions,
};

use crate::errors::ExternalSignatureProgramError;

use super::{
    AccountSeedsTrait, ExecutionAccount, ExternallySignedAccountData, SessionKey,
    SignerExecutionScheme,
};

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

/// Implementation for the account header
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

/// Wrapper around the account data
pub struct ExternallySignedAccount<'a, T: ExternallySignedAccountData> {
    phantom: PhantomData<T>,
    pub account_info: &'a AccountInfo,
    data: &'a mut [u8],
}

/// Core functionality implementations
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Returns the key of the account
    pub fn key(&self) -> &Pubkey {
        self.account_info.key()
    }

    /// Returns the size of the account data
    pub fn size() -> usize {
        core::mem::size_of::<T>()
    }

    /// Loads the account
    pub fn load(account_info: &'a AccountInfo) -> Result<Self, ProgramError> {
        // Will fail if the account is not writable
        let mut data = account_info.try_borrow_mut_data()?;

        if account_info.data_is_empty() {
            assert_eq!(unsafe { account_info.owner() }, &pinocchio_system::ID);
        } else {
            assert_eq!(unsafe { account_info.owner() }, &crate::ID);
        }

        let data_ptr = data.as_mut_ptr(); // Get a raw pointer to the data
                                          // Won't be outlived, since the accountInfo is loaded in at the
                                          // instruction level
        let data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(data_ptr, data.len()) };
        Ok(Self {
            phantom: PhantomData,
            account_info,
            data: data_slice,
        })
    }

    /// Reloads the account data
    pub fn reload(&mut self) -> Result<(), ProgramError> {
        let mut reloaded_data = self.account_info.try_borrow_mut_data()?;
        let reloaded_data_ptr = reloaded_data.as_mut_ptr();
        let reloaded_data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(reloaded_data_ptr, reloaded_data.len()) };
        self.data = reloaded_data_slice;
        Ok(())
    }

    /// Returns a mutable reference to the account data
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

    /// Returns a readonly reference to the account data
    pub fn data_ref(&'a self) -> Result<&'a T, ProgramError> {
        let header = self.header();

        if header.version() != T::version() || header.scheme() != T::scheme() {
            return Err(ExternalSignatureProgramError::ErrorDeserializingHeader.into());
        }
        if self.data.len() < T::size() {
            return Err(ExternalSignatureProgramError::ErrorDeserializingAccountData.into());
        }
        Ok(bytemuck::try_from_bytes::<T>(&self.data[..T::size()])
            .map_err(|_| ExternalSignatureProgramError::ErrorDeserializingAccountData)?)
    }
}

/// Header operations
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Returns a readonly reference to the header
    pub fn header_ref(&self) -> &AccountHeader {
        bytemuck::from_bytes::<AccountHeader>(&self.data[0..AccountHeader::size()])
    }

    /// Returns a mutable reference to the header
    pub fn header(&self) -> &mut AccountHeader {
        // Since we know ExternallyOwnedAccountMut is a mutable reference, we
        // can safely return a mutable reference to the header
        let data_ptr = self.data as *const [u8] as *mut [u8];
        unsafe {
            bytemuck::from_bytes_mut::<AccountHeader>(&mut (*data_ptr)[0..AccountHeader::size()])
        }
    }

    /// Initializes the header with the correct version and scheme
    pub fn initialize_header(&mut self) {
        let header =
            bytemuck::from_bytes_mut::<AccountHeader>(&mut self.data[0..AccountHeader::size()]);
        header.set::<T>();
    }
}

/// Account derivation operations
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Checks the account based on the parsed verification data
    pub fn check_account(
        &self,
        args: &T::ParsedVerificationData,
    ) -> Result<T::AccountSeeds, ProgramError> {
        let data = self.data_ref()?;
        T::check_account(&data, self.account_info, args)
    }
    /// Derives a new account from args
    pub fn derive_account(args: T::DeriveAccountArgs) -> Result<T::AccountSeeds, ProgramError> {
        T::derive_account(args)
    }

    /// Derives an existing account from the account data
    pub fn derive_existing_account(&self) -> Result<T::AccountSeeds, ProgramError> {
        let data = self.data_ref()?;
        T::derive_existing_account(data)
    }
}

/// Initialization and verification operations
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Returns the signature scheme specific initialization payload
    pub fn get_initialization_payload(&self) -> &'static [u8] {
        T::get_initialization_payload()
    }

    /// Initializes the account, including the header
    pub fn initialize_account(
        &mut self,
        args: &T::ParsedInitializationData,
        session_key: Option<SessionKey>,
    ) -> Result<(), ProgramError> {
        self.initialize_header();
        let data = self.data()?;
        T::initialize_account(data, &args, session_key)?;
        Ok(())
    }

    /// Verifies an initialization payload
    pub fn verify_initialization_payload<'b>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'b, [u8]>>,
        initialization_data: &T::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::verify_initialization_payload(
            data,
            instructions_sysvar_account,
            initialization_data,
            payload,
        )
    }

    /// Verifies an instruction execution payload
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
}

/// Session key management
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Checks if a session key is valid
    pub fn is_valid_session_key(&self, signer: &AccountInfo) -> Result<(), ProgramError> {
        let data = self.data_ref()?;
        T::is_valid_session_key(data, signer)
    }

    /// Updates the session key
    pub fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        let data = self.data()?;
        T::update_session_key(data, session_key)?;
        Ok(())
    }
}

/// Execution account management
impl<'a, T: ExternallySignedAccountData> ExternallySignedAccount<'a, T> {
    /// Returns the execution account for the account based on the signer execution scheme
    pub fn get_execution_account(
        &self,
        signer_execution_scheme: SignerExecutionScheme,
    ) -> Result<ExecutionAccount, ProgramError> {
        let (executing_account, seeds, bump): (Pubkey, [Vec<u8>; 2], u8) =
            match signer_execution_scheme {
                SignerExecutionScheme::ExecutionAccount => {
                    let seeds = [self.account_info.key().as_slice(), b"execution_account"];
                    let (execution_account, bump) =
                        try_find_program_address(&seeds, &crate::ID).unwrap();
                    let seeds_vec: [Vec<u8>; 2] = seeds.map(|s| s.to_vec());
                    (execution_account, seeds_vec, bump)
                }
                SignerExecutionScheme::ExternalAccount => {
                    let external_account_seeds = self.derive_existing_account()?;
                    let seeds = external_account_seeds.seeds_owned();

                    (
                        external_account_seeds.key().to_owned(),
                        seeds,
                        external_account_seeds.bump(),
                    )
                }
            };

        Ok(ExecutionAccount {
            key: executing_account,
            bump,
            seeds,
        })
    }
}
