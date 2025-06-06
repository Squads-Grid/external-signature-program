use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, sysvars::instructions::Instructions,
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    utils::{PrecompileParser, Secp256r1Precompile},
};

const MESSAGE: &[u8] = b"helloworld";

pub fn process_verify(accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let (sysvar_account, _remaining) = if let [sysvar_account, remaining @ ..] = accounts {
        (sysvar_account, remaining)
    } else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // get instructions sysvar account
    let instructions = Instructions::try_from(sysvar_account)?;

    // load precompile instructions from sysvar account at index 0
    let precompile_instruction = instructions.load_instruction_at(0)?;

    // parse precompile instruction
    let parser =
        PrecompileParser::<Secp256r1Precompile>::new(&precompile_instruction, &instructions)?;
    let num_signatures = parser.num_signatures();

    // get signature payload
    let signature_payload = parser.get_signature_payload_at(0)?;

    // check if number of signatures is correct
    if num_signatures != 2 {
        return Err(ProgramError::Custom(
            ExternalSignatureProgramError::InvalidNumPrecompileSignatures as u32,
        ));
    }

    // finally, check if signature payload is correct
    assert_eq!(signature_payload.message, MESSAGE);

    Ok(())
}
