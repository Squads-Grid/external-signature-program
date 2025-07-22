use std::fs;

use borsh::{to_vec, BorshSerialize};
use external_signature_program::{
    instructions::refresh_session_key::RefreshSessionKeyArgs,
    state::{P256RawVerificationData, SessionKey},
    utils::signatures::{AuthType, ClientDataJsonReconstructionParams},
    utils::{SmallVec, TruncatedSlot, SLOT_HASHES_ID},
};
use litesvm::LiteSVM;
use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::p256::utils::{
    instruction_and_payload_generation::get_execution_account, parser::parse_webauthn_fixture,
    secp256r1_instruction::new_secp256r1_instruction,
};

pub const TESTING_SESSION_KEY: SessionKey = SessionKey {
    key: Pubkey::from_str_const("sesfSDjioiWGpxqSoHSfMGrQe3wAyEBDSAL3niVecdC").to_bytes(),
    expiration: 900,
};

pub fn refresh_session_key(
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
    svm.airdrop(&execution_account, 1000000000).unwrap();

    let external_sig_ix_data = RefreshSessionKeyArgs {
        signature_scheme: 0,
        verification_data: SmallVec::<u8, u8>::try_from(to_vec(&extra_verification_data).unwrap())
            .unwrap(),
        session_key: TESTING_SESSION_KEY,
        slothash: slot_num,
    };
    let mut serialized_ix_data: Vec<u8> = vec![];
    // Discriminator
    serialized_ix_data.push(2);
    // Instruction data
    external_sig_ix_data
        .serialize(&mut serialized_ix_data)
        .unwrap();
    // Instruction
    let external_sig_ix = Instruction {
        program_id: program_id.clone(),
        accounts: vec![
            AccountMeta::new(passkey_account.clone(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new(payer.clone(), true),
        ],
        data: serialized_ix_data,
    };
    Ok(vec![instruction, external_sig_ix])
}
