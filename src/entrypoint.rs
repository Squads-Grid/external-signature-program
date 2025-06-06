use crate::allocator::BumpAllocator;
use crate::instructions::*;
use execute_instructions::native::process_execute_instructions;
use initialize_account::process_initialize_account;
use pinocchio::{
    account_info::AccountInfo, nostd_panic_handler, entrypoint::HEAP_START_ADDRESS, log, msg, program_entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult
};
use refresh_session_key::process_refresh_session_key;

// Entrypoint Configuration
#[cfg(target_os = "solana")]
#[global_allocator]
pub static A: BumpAllocator = BumpAllocator;
program_entrypoint!(process_instruction);
// Only use the allocator if we're targeting the deployable program binary

/// Process an instruction
/// 0 - Create Account
/// 1 - Execute with CPI
/// 2 - Sign Message
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, instruction_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match discriminator {
        // 0 - Create Account
        0 => {
            process_initialize_account(accounts, instruction_data)?;
        }
        // 1 - Execute with CPI
        1 => {
            msg!("Executing with CPI");
            process_execute_instructions(accounts, instruction_data)?;
        }
        // 2 - Refresh Session Key
        2 => {
            process_refresh_session_key(accounts, instruction_data)?;
        }
        // 3 - Verify Message
        3 => {
            verify::process_verify(accounts, instruction_data)?;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    Ok(())
}
