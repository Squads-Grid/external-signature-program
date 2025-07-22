use std::fs;

use borsh::to_vec;
use external_signature_program::{
    instructions::initialize_external_account::InitializeAccountArgs,
    state::{P256RawInitializationData, SignatureScheme},
    utils::{nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID},
};
use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program::ID as SYSTEM_PROGRAM_ID,
};

use crate::p256::utils::{
    parser::parse_webauthn_fixture, secp256r1_instruction::new_secp256r1_instruction,
};

/// Returns a tuple containing:
/// 1. The pubkey of the initialized account
/// 2. A vector of instructions (precompile verification, transfer, and initialization)
pub fn initialize_passkey_account(
    fixture_path: &str,
    payer: &Pubkey,
    slot_num: &TruncatedSlot,
    program_id: &Pubkey,
) -> Result<(Pubkey, Vec<u8>, Vec<Instruction>), Box<dyn std::error::Error>> {
    // Read and parse the WebAuthn fixture
    let json_data = fs::read_to_string(fixture_path)?;
    let webauthn_data = parse_webauthn_fixture(&json_data)?;

    // println!("WebAuthn data: {:#?}", webauthn_data);
    // println!("Client data json: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.client_data_json));
    // println!("Auth data: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.auth_data));
    // println!("Signature: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.signature));
    // println!("Sig Length: {:#?}", webauthn_data.signature.len());
    // Prepare message for secp256r1 verification
    let mut message = webauthn_data.auth_data.clone();
    let client_data_hash = solana_nostd_sha256::hashv(&[&webauthn_data.client_data_json]);
    message.extend_from_slice(&client_data_hash);

    // Get the public key from the fixture data
    let public_key = webauthn_data.public_key.unwrap();
    // Create secp256r1 verification instruction
    let precompile_ix =
        new_secp256r1_instruction(&webauthn_data.signature, &message, &public_key, None)?;

    // Calculate public key hash
    let public_key_hash = solana_nostd_sha256::hashv(&[&public_key]);

    // RP ID for the passkey (relay party identifier)
    let rp_id = b"www.passkeys-debugger.io";

    // Define the seeds for the passkey account
    let seeds: [&[u8]; 2] = [b"passkey", public_key_hash.as_slice()];

    // Find the program-derived address for the account
    let (account_to_initialize, _account_bump) =
        Pubkey::try_find_program_address(&seeds, program_id).unwrap();

    // Construct the initialization instruction data
    let p256_webauthn_args = P256RawInitializationData {
        rp_id: SmallVec::<u8, u8>::try_from(rp_id.to_vec()).unwrap(),
        public_key: public_key.as_slice().try_into().unwrap(),
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .into(),
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_num.clone(),
        signature_scheme: SignatureScheme::P256Webauthn.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(to_vec(&p256_webauthn_args).unwrap())
            .unwrap(),
        session_key: None,
    };

    let mut instruction_data = Vec::with_capacity(1 + 1 + public_key.len() + 1 + rp_id.len());
    instruction_data.push(0); // instruction discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args).unwrap());

    // Create the account initialization instruction
    let initialize_account_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    // Combine all instructions into a Vec
    let instructions = vec![precompile_ix, initialize_account_ix];

    Ok((account_to_initialize, public_key, instructions))
}
