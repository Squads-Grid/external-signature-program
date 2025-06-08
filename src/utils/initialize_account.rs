use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};

pub fn initialize_account(
    account_to_initialize: &AccountInfo,
    rent_payer: &AccountInfo,
    space: usize,
    seeds: &[&[u8]],
) -> Result<(), ProgramError> {
    // Define the seeds for PDA signing
    let seeds = seeds
        .iter()
        .map(|seed| Seed::from(*seed))
        .collect::<Vec<Seed>>();
    let external_account_signer = [Signer::from(seeds.as_slice())];

    // Get required lamports for space
    let required_lamports = Rent::get()?.minimum_balance(space);

    // Transfer lamports
    Transfer {
        from: rent_payer,
        to: account_to_initialize,
        lamports: required_lamports,
    }
    .invoke()?;

    // Allocate space
    Allocate {
        account: account_to_initialize,
        space: space as u64,
    }
    .invoke_signed(&external_account_signer)?;

    // Assign account to program
    Assign {
        account: account_to_initialize,
        owner: &crate::ID,
    }
    .invoke_signed(&external_account_signer)?;
    Ok(())
}
