use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

pub fn check_account_uninitialized(account: &AccountInfo) -> Result<(), ProgramError> {
    if !account.is_owned_by(&pinocchio_system::ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if !account.data_is_empty() {
        return Err(ProgramError::InvalidAccountData);
    };
    Ok(())
}
