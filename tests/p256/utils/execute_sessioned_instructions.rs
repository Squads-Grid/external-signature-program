use std::fs;

use borsh::{to_vec, BorshSerialize};
use external_signature_program::{
    checks::nonce::TruncatedSlot,
    instructions::execute_instructions::sessioned::ExecutableInstructionArgs,
    signatures::{AuthType, ClientDataJsonReconstructionParams},
    state::P256WebauthnRawVerificationData,
    utils::{SmallVec, SLOT_HASHES_ID},
};
use litesvm::LiteSVM;
use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;
use solana_keypair::Keypair;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use crate::p256::utils::{
    instruction_and_payload_generation::{
        create_instruction_payload, create_memo_instruction, create_system_transfer_instruction,
        get_execution_account, serialize_compiled_instruction,
    },
    parser::parse_webauthn_fixture,
    secp256r1_instruction::new_secp256r1_instruction,
};

pub fn execute_sessioned_instructions(
    session_keypair: &Keypair,
    svm: &mut LiteSVM,
    passkey_account: &Pubkey,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>, Box<dyn std::error::Error>> {
    let execution_account = get_execution_account(passkey_account.clone(), program_id.clone());
    svm.expire_blockhash();
    svm.airdrop(&execution_account, 1000000000).unwrap();

    let memo_instruction = create_memo_instruction();
    let system_transfer_instruction = create_system_transfer_instruction(execution_account);
    let instructions = vec![memo_instruction, system_transfer_instruction];
    // Instruction data
    let (account_metas, compiled_instruction) = create_instruction_payload(instructions);
    let serialized_compiled_instruction = serialize_compiled_instruction(compiled_instruction);
    let external_sig_ix_data = ExecutableInstructionArgs {
        signature_scheme: 0,
        instructions: serialized_compiled_instruction,
    };
    let mut serialized_ix_data: Vec<u8> = vec![];
    // Discriminator
    serialized_ix_data.push(3);
    // Instruction data
    external_sig_ix_data
        .serialize(&mut serialized_ix_data)
        .unwrap();
    //println!("public_key: {:#?}", public_key);
    //println!("serialized_ix_data: {:#?}", serialized_ix_data);
    // Instruction
    let external_sig_ix = Instruction {
        program_id: program_id.clone(),
        accounts: vec![
            AccountMeta::new(passkey_account.clone(), false),
            AccountMeta::new(session_keypair.pubkey(), true),
        ]
        .into_iter()
        .chain(account_metas.into_iter())
        .collect(),
        data: serialized_ix_data,
    };
    Ok((vec![external_sig_ix]))
}
