use std::time::{SystemTime, UNIX_EPOCH};

use external_signature_program::{
    errors::ExternalSignatureProgramError, utils::nonce::TruncatedSlot, ID as PROGRAM_ID,
};
use litesvm::{types::FailedTransactionMetadata, LiteSVM};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::{
    clock::Clock,
    instruction::{Instruction, InstructionError},
    native_token::LAMPORTS_PER_SOL,
};
use solana_pubkey::Pubkey;
use solana_slot_hashes::{SlotHash, SlotHashes};
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

pub fn create_and_send_svm_transaction(
    svm: &mut LiteSVM,
    instructions: Vec<Instruction>,
    payer: &Pubkey,
    signers: Vec<&Keypair>,
) -> Result<(), FailedTransactionMetadata> {
    let blockhash = svm.latest_blockhash();
    let message = Message::new_with_blockhash(&instructions, Some(&payer), &blockhash);
    let tx = Transaction::new(&signers, message, blockhash);
    let result = svm.send_transaction(tx);
    match &result {
        Ok(tx) => {
            println!(
                "CUs consumed: {:?}, Signature: {:?}",
                tx.compute_units_consumed, tx.signature
            );
        }
        Err(e) => {
            return Err((*e).clone());
        }
    }
    Ok(())
}

pub fn create_and_assert_svm_transaction(
    svm: &mut LiteSVM,
    instructions: Vec<Instruction>,
    payer: &Pubkey,
    signers: Vec<&Keypair>,
    expected_error: Option<ExternalSignatureProgramError>,
) -> Result<(), FailedTransactionMetadata> {
    let result = create_and_send_svm_transaction(svm, instructions, payer, signers);

    match (result, expected_error) {
        (Ok(_), None) => Ok(()),
        (Ok(_), Some(_)) => panic!("Expected error but transaction succeeded"),
        (Err(error), None) => panic!("Unexpected error: {:?}", error),
        (Err(error), Some(expected)) => match error.err {
            TransactionError::InstructionError(_, InstructionError::Custom(value)) => {
                match ExternalSignatureProgramError::try_from(value.clone()) {
                    Ok(actual_error) => {
                        assert_eq!(
                            actual_error, expected,
                            "Expected error {:?} but got {:?} /n Error: {:?}",
                            expected, actual_error, error
                        );
                        Ok(())
                    }
                    Err(_) => panic!("Failed to parse custom error: {:?}", error),
                }
            }
            _ => panic!("Unexpected error type: {:?}", error),
        },
    }
}

pub fn add_external_signature_program(svm: &mut LiteSVM) -> Pubkey {
    let program_id = Pubkey::new_from_array(PROGRAM_ID);
    svm.add_program_from_file(program_id, "./target/deploy/external_signature_program.so")
        .unwrap();
    program_id
}

pub fn initialize_svm(airdrop_keys: Vec<Pubkey>) -> (LiteSVM, Pubkey) {
    let mut svm = LiteSVM::new();
    for key in airdrop_keys {
        svm.airdrop(&key, 10 * LAMPORTS_PER_SOL).unwrap();
    }
    let program_id = add_external_signature_program(&mut svm);
    set_slothash_sysvar(&mut svm);
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    svm.set_sysvar::<Clock>(&clock);
    (svm, program_id)
}

pub fn set_slothash_sysvar(svm: &mut LiteSVM) {
    let mut slothashes: Vec<SlotHash> = Vec::new();
    for i in 0..512u64 {
        // Create a byte representation of the slot number
        let slot_bytes = i.to_le_bytes();

        // Hash the slot bytes using SHA-256
        let hash_result = Sha256::digest(&slot_bytes);

        // Convert the digest into a fixed-size array
        let hash_bytes: [u8; 32] = hash_result.into();

        // Create a SlotHash which is (Slot, Hash)
        let slot_hash: SlotHash = (i, Hash::from(hash_bytes));

        slothashes.push(slot_hash);
    }
    svm.set_sysvar(&SlotHashes::new(&slothashes));
}

pub fn get_valid_slothash(svm: &LiteSVM) -> ([u8; 32], TruncatedSlot) {
    let slothashes = svm.get_sysvar::<SlotHashes>();
    // Meaning of life
    let slot = slothashes[42];
    let truncated_slot = slot.0 % 1000;
    let truncated_slot = TruncatedSlot(truncated_slot as u16);
    println!("Valid slothash: {:?}", truncated_slot.0);
    (slot.1.to_bytes(), truncated_slot)
}

pub fn get_expired_slothash(svm: &LiteSVM) -> ([u8; 32], TruncatedSlot) {
    let slothashes = svm.get_sysvar::<SlotHashes>();
    let slot = slothashes[170];
    let truncated_slot = slot.0 % 1000;
    let truncated_slot = TruncatedSlot(truncated_slot as u16);
    (slot.1.to_bytes(), truncated_slot)
}
