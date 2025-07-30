use std::{fs, str::FromStr};

use base64::{engine::general_purpose, Engine as _};
use borsh::BorshSerialize;
use external_signature_program::{
    utils::instructions::CompiledInstruction as ExternalCompiledInstruction, utils::SmallVec,
    ID as PROGRAM_ID,
};
use sha2::{Digest, Sha256};
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_program::instruction::{AccountMeta, CompiledInstruction, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::{EncodableKey, Signer};

use crate::{
    p256::utils::{
        parser::parse_webauthn_fixture,
        svm::{get_valid_slothash, initialize_svm},
    },
    refresh_session_key::TESTING_SESSION_KEY,
};

pub fn get_execution_account(account: Pubkey, program_id: Pubkey) -> Pubkey {
    let seeds = [account.as_ref(), b"execution_account"];
    let (execution_account, _bump) = Pubkey::try_find_program_address(&seeds, &program_id).unwrap();
    execution_account
}
pub fn serialize_compiled_instruction(
    compiled_instructions: Vec<CompiledInstruction>,
) -> SmallVec<u8, ExternalCompiledInstruction> {
    let custom_compiled_instruction: Vec<ExternalCompiledInstruction> = compiled_instructions
        .iter()
        .map(|compiled_instruction| ExternalCompiledInstruction {
            program_id_index: compiled_instruction.program_id_index,
            accounts_indices: SmallVec::<u8, u8>::try_from(compiled_instruction.accounts.clone())
                .unwrap(),
            data: SmallVec::<u16, u8>::try_from(compiled_instruction.data.clone()).unwrap(),
        })
        .collect();
    SmallVec::<u8, ExternalCompiledInstruction>::try_from(custom_compiled_instruction).unwrap()
}
pub fn create_memo_instruction() -> Instruction {
    let memo_program_id = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
    let signer_bytes: Vec<u8> = serde_json::from_str(include_str!(
        "../keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json"
    ))
    .unwrap();
    let signer = Keypair::from_bytes(&signer_bytes).unwrap();
    let account_metas = vec![AccountMeta::new(signer.pubkey(), true)];

    let memo_instruction = Instruction {
        program_id: memo_program_id,
        accounts: account_metas.clone(),
        data: vec![],
    };
    memo_instruction
}

pub fn create_system_transfer_instruction(execution_account: Pubkey) -> Instruction {
    let to_pubkey = Pubkey::from_str("sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB").unwrap();
    let mut instruction =
        solana_program::system_instruction::transfer(&execution_account, &to_pubkey, 1000000000);
    // Set the account to not be a signer since its signature only gets added
    // during CPI
    instruction
        .accounts
        .iter_mut()
        .find(|account_meta| account_meta.pubkey == execution_account)
        .unwrap()
        .is_signer = false;
    instruction
}
pub fn create_instruction_payload(
    instructions: Vec<Instruction>,
) -> (Vec<AccountMeta>, Vec<CompiledInstruction>) {
    let signer_bytes: Vec<u8> = serde_json::from_str(include_str!(
        "../keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json"
    ))
    .unwrap();
    let signer = Keypair::from_bytes(&signer_bytes).unwrap();

    let message = VersionedMessage::Legacy(solana_message::legacy::Message::new(
        &instructions,
        Some(&signer.pubkey()),
    ));
    let compiled_instructions = message.instructions();

    let header = message.header();
    let account_keys = message.static_account_keys();
    let mut account_metas = Vec::new();

    // Calculate indices for different account sections based on header
    let writable_signed_end = header.num_required_signatures - header.num_readonly_signed_accounts;
    let signed_end = header.num_required_signatures;
    let writable_unsigned_end = account_keys.len() - header.num_readonly_unsigned_accounts as usize;

    // Process accounts in order based on header info
    for (i, key) in account_keys.iter().enumerate() {
        let is_signer = i < signed_end as usize;
        let is_writable = if is_signer {
            i < writable_signed_end as usize
        } else {
            i < writable_unsigned_end
        };

        account_metas.push(AccountMeta {
            pubkey: *key,
            is_signer,
            is_writable,
        });
    }
    (account_metas, compiled_instructions.to_vec())
}

#[test]
pub fn print_instruction_payload() {
    let program_id = Pubkey::new_from_array(PROGRAM_ID);

    // Modify this line to change what fixture the payload is generated for
    // #########################################################
    let json_data =
        fs::read_to_string("tests/p256/fixtures/ios-crossplatform/creation.json").unwrap();
    // #########################################################

    let webauthn_data = parse_webauthn_fixture(&json_data).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&webauthn_data.public_key.unwrap());
    let pubkey_hash = hasher.finalize();
    let (passkey_account, _) =
        Pubkey::try_find_program_address(&[b"passkey", pubkey_hash.as_slice()], &program_id)
            .unwrap();
    //println!("passkey_account: {:?}", passkey_account);
    let (execution_account, _) = Pubkey::try_find_program_address(
        &[passkey_account.as_ref(), b"execution_account"],
        &program_id,
    )
    .unwrap();
    let memo_instruction = create_memo_instruction();
    let system_transfer_instruction = create_system_transfer_instruction(execution_account);
    let instructions = vec![memo_instruction, system_transfer_instruction];
    let (account_metas, compiled_instructions) = create_instruction_payload(instructions);
    let nonce_signer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (svm, _) = initialize_svm(vec![nonce_signer.pubkey()]);
    let (hash, _) = get_valid_slothash(&svm);

    let mut instruction_bytes: Vec<u8> = Vec::new();
    instruction_bytes.extend_from_slice(&hash);
    instruction_bytes.extend_from_slice(&nonce_signer.pubkey().to_bytes());
    instruction_bytes.extend_from_slice(b"execute_instructions");
    instruction_bytes.push(account_metas.len() as u8);
    for account_meta in account_metas {
        instruction_bytes.extend_from_slice(&account_meta.pubkey.to_bytes());
        instruction_bytes.push(account_meta.is_signer as u8);
        instruction_bytes.push(account_meta.is_writable as u8);
    }
    let custom_compiled_instructions = serialize_compiled_instruction(compiled_instructions);

    custom_compiled_instructions
        .serialize(&mut instruction_bytes)
        .unwrap();

    let _instruction_bytes_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&instruction_bytes);
    //println!("instruction_bytes_base64: {:?}", instruction_bytes_base64);
    let mut hasher = Sha256::new();
    hasher.update(&instruction_bytes);
    let result = hasher.finalize();

    //println!("instruction_hash_bytes: {:?}", result);
    let base64_url_encoded_instruction_hash = general_purpose::URL_SAFE_NO_PAD.encode(result);
    println!(
        "challenge payload: {:?}",
        base64_url_encoded_instruction_hash
    );
}

#[test]
pub fn print_initialization_payload() {
    let nonce_signer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (svm, _) = initialize_svm(vec![nonce_signer.pubkey()]);
    let (hash, _) = get_valid_slothash(&svm);

    let mut instruction_bytes: Vec<u8> = Vec::new();
    instruction_bytes.extend_from_slice(&hash);
    instruction_bytes.extend_from_slice(&nonce_signer.pubkey().to_bytes());
    instruction_bytes.extend_from_slice(b"initialize_passkey");

    let mut hasher = Sha256::new();
    hasher.update(&instruction_bytes);
    let result = hasher.finalize();

    let base64_url_encoded_instruction_hash = general_purpose::URL_SAFE_NO_PAD.encode(result);

    println!(
        "challenge payload: {:?}",
        base64_url_encoded_instruction_hash
    );
}

#[test]
pub fn print_session_key_payload() {
    let nonce_signer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();

    let _session_key = Keypair::read_from_file(
        "tests/p256/keypairs/sesfSDjioiWGpxqSoHSfMGrQe3wAyEBDSAL3niVecdC.json",
    )
    .unwrap();
    let (svm, _) = initialize_svm(vec![nonce_signer.pubkey()]);
    let (hash, _) = get_valid_slothash(&svm);

    let mut instruction_bytes: Vec<u8> = Vec::new();
    instruction_bytes.extend_from_slice(&hash);
    instruction_bytes.extend_from_slice(&nonce_signer.pubkey().to_bytes());
    instruction_bytes.extend_from_slice(b"refresh_session_key");
    TESTING_SESSION_KEY
        .serialize(&mut instruction_bytes)
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&instruction_bytes);
    let result = hasher.finalize();

    let base64_url_encoded_instruction_hash = general_purpose::URL_SAFE_NO_PAD.encode(result);

    println!(
        "challenge payload: {:?}",
        base64_url_encoded_instruction_hash
    );
}
