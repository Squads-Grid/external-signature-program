use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
    ProgramResult,
};
use pinocchio_pubkey::pubkey;

use crate::{errors::ExternalSignatureProgramError, utils::{PrecompileParser, Secp256r1Precompile}};

const MESSAGE: &[u8] = b"helloworld";


pub fn process_verify(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (sysvar_account, remaining) = if let [sysvar_account, remaining @ ..] = accounts {
        (sysvar_account, remaining)
    } else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let instructions = Instructions::try_from(sysvar_account)?;

    let precompile_instruction = instructions.load_instruction_at(0)?;

    let parser =
        PrecompileParser::<Secp256r1Precompile>::new(&precompile_instruction, &instructions)?;
    let num_signatures = parser.num_signatures();
    let signature_payload = parser.get_signature_payload_at(0)?;

    if num_signatures != 2 {
        return Err(ProgramError::Custom(
            ExternalSignatureProgramError::InvalidNumPrecompileSignatures as u32,
        ));
    }

    assert_eq!(signature_payload.message, MESSAGE);
    Ok(())
}
