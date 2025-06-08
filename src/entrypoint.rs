use pinocchio::{
    account_info::AccountInfo, program_entrypoint, program_error::ProgramError, pubkey::Pubkey,
    ProgramResult,
};

use crate::instructions::{
    process_execute_instructions, process_execute_instructions_sessioned,
    process_initialize_external_account, process_refresh_session_key,
};

// Entrypoint Configuration
#[cfg(target_os = "solana")]
#[global_allocator]
pub static A: crate::allocator::BumpAllocator = crate::allocator::BumpAllocator;
program_entrypoint!(process_instruction);
// Only use the allocator if we're targeting the deployable program binary

/// Process an instruction
/// 0 - Initialize Account
/// 1 - Execute instructions
/// 2 - Refresh Session Key
/// 3 - Execute with Session Key
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, instruction_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match discriminator {
        0 => process_initialize_external_account(accounts, instruction_data),
        1 => process_execute_instructions(accounts, instruction_data),
        2 => process_refresh_session_key(accounts, instruction_data),
        3 => process_execute_instructions_sessioned(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
