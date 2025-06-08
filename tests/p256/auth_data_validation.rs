use crate::p256::utils::svm::get_valid_slothash;
use crate::p256::utils::{initialization::initialize_passkey_account, svm::initialize_svm};
use external_signature_program::errors::ExternalSignatureProgramError;
use solana_keypair::Keypair;
use solana_signer::{EncodableKey, Signer};

use super::svm::create_and_assert_svm_transaction;

#[allow(unused)]
fn test_invalid_auth_data(path: &str, error: ExternalSignatureProgramError) {
    let payer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (mut svm, program_id) = initialize_svm(vec![payer.pubkey()]);

    let (_hash, truncated_slot) = get_valid_slothash(&svm);
    // Get the passkey account and instructions from our abstracted function
    let (_account_pubkey, _public_key, instructions) =
        initialize_passkey_account(path, &payer.pubkey(), &truncated_slot, &program_id).unwrap();

    // Create and submit the transaction
    create_and_assert_svm_transaction(
        &mut svm,
        instructions,
        &payer.pubkey(),
        vec![&payer],
        Some(error),
    )
    .unwrap();
}
