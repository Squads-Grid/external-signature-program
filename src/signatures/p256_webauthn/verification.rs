use bytemuck::{Pod, Zeroable};
use pinocchio::{pubkey::Pubkey, sysvars::instructions::Instructions, ProgramResult};
use pinocchio_pubkey::pubkey;

use crate::errors::ExternalSignatureProgramError;

pub const SECP256R1_PRECOMPILE_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");

#[derive(Default, Debug, Copy, Zeroable, Pod, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Secp256r1SignatureOffsets {
    /// Offset to compact secp256r1 signature of 64 bytes
    pub signature_offset: u16,

    /// Instruction index where the signature can be found
    pub signature_instruction_index: u16,

    /// Offset to compressed public key of 33 bytes
    pub public_key_offset: u16,

    /// Instruction index where the public key can be found
    pub public_key_instruction_index: u16,

    /// Offset to the start of message data
    pub message_data_offset: u16,

    /// Size of message data in bytes
    pub message_data_size: u16,

    /// Instruction index where the message data can be found
    pub message_instruction_index: u16,
}

pub fn verify_registration(
    precompile_instruction_index: u8,
    _rp_id: &[u8],
    instructions_sysvar_data: &[u8],
) -> ProgramResult {
    let instructions = unsafe { Instructions::new_unchecked(instructions_sysvar_data) };

    let secp256r1_instruction =
        instructions.load_instruction_at(precompile_instruction_index as usize)?;

    // Check instruction for the correct precompile id
    if secp256r1_instruction.get_program_id() != &SECP256R1_PRECOMPILE_ID {
        return Err(ExternalSignatureProgramError::InvalidPrecompileId.into());
    }

    let data = secp256r1_instruction.get_instruction_data();

    let num_signatures = data[0];

    if num_signatures != 1 {
        return Err(ExternalSignatureProgramError::InvalidNumPrecompileSignatures.into());
    }
    Ok(())
}
