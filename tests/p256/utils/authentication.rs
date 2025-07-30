use std::fs;

use borsh::{to_vec, BorshSerialize};
use external_signature_program::{
    instructions::execute_instructions::ExecutableInstructionArgs,
    state::P256RawVerificationData,
    utils::signatures::{AuthType, ClientDataJsonReconstructionParams},
    utils::{nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID},
};
use litesvm::LiteSVM;
use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::p256::utils::{
    instruction_and_payload_generation::{
        create_instruction_payload, create_memo_instruction, create_system_transfer_instruction,
        get_execution_account, serialize_compiled_instruction,
    },
    parser::parse_webauthn_fixture,
    secp256r1_instruction::new_secp256r1_instruction,
};

pub fn authenticate_passkey_account(
    fixture_path: &str,
    svm: &mut LiteSVM,
    passkey_account: &Pubkey,
    payer: &Pubkey,
    slot_num: TruncatedSlot,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>, Box<dyn std::error::Error>> {
    let json_data = fs::read_to_string(fixture_path).expect("Unable to read fixture file");
    let webauthn_data = parse_webauthn_fixture(&json_data).unwrap();
    let public_key = webauthn_data.public_key.unwrap();
    let client_data_hash = solana_nostd_sha256::hashv(&[&webauthn_data.client_data_json]);
    let mut message_data = webauthn_data.auth_data.clone();
    message_data.extend_from_slice(&client_data_hash);
    let instruction =
        new_secp256r1_instruction(&webauthn_data.signature, &message_data, &public_key, None)
            .unwrap();

    let extra_verification_data = P256RawVerificationData {
        public_key: public_key.clone().try_into().unwrap(),
        client_data_json_reconstruction_params: webauthn_data.client_data_json_reconstruction_params,
    };

    let execution_account = get_execution_account(passkey_account.clone(), program_id.clone());
    println!("execution_account: {:?}", execution_account.to_string());
    svm.airdrop(&execution_account, 1000000000).unwrap();

    let memo_instruction = create_memo_instruction();
    let system_transfer_instruction = create_system_transfer_instruction(execution_account);
    let instructions = vec![memo_instruction, system_transfer_instruction];
    // Instruction data
    let (account_metas, compiled_instruction) = create_instruction_payload(instructions);
    let serialized_compiled_instruction = serialize_compiled_instruction(compiled_instruction);
    let external_sig_ix_data = ExecutableInstructionArgs {
        signature_scheme: 0,
        signer_execution_scheme: 0,
        extra_verification_data: SmallVec::<u8, u8>::try_from(to_vec(&extra_verification_data).unwrap())
            .unwrap(),
        instructions: serialized_compiled_instruction,
        slothash: slot_num,
    };
    let mut serialized_ix_data: Vec<u8> = vec![];
    // Discriminator
    serialized_ix_data.push(1);
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
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new(payer.clone(), true),
        ]
        .into_iter()
        .chain(account_metas.into_iter())
        .collect(),
        data: serialized_ix_data,
    };
    Ok(vec![instruction, external_sig_ix])
}
