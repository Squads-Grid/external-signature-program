use crate::{
    p256::utils::{
        authentication::authenticate_passkey_account,
        initialization::initialize_passkey_account,
        svm::{create_and_send_svm_transaction, get_valid_slothash, initialize_svm},
    },
    svm::{create_and_assert_svm_transaction, get_expired_slothash},
};
use external_signature_program::errors::ExternalSignatureProgramError;
use solana_keypair::Keypair;
use solana_signer::{EncodableKey, Signer};

fn test_authentication_from_fixture(create_account_path: &str, auth_path: &str) {
    let payer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (mut svm, program_id) = initialize_svm(vec![payer.pubkey()]);

    let (hash, truncated_slot) = get_valid_slothash(&svm);
    println!("Hash: {:?}", hash);
    // Get the passkey account and instructions from our abstracted function
    let (account_pubkey, _public_key, instructions) = initialize_passkey_account(
        create_account_path,
        &payer.pubkey(),
        &truncated_slot,
        &program_id,
    )
    .unwrap();

    // Print the account information for debugging
    println!("Account to initialize: {:?}", account_pubkey);

    // Create and submit the transaction
    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();

    println!("Account created");
    // Verify the account was properly created
    let account = svm.get_account(&account_pubkey).unwrap();
    assert_eq!(account.data.len() > 0, true);

    let instructions = authenticate_passkey_account(
        auth_path,
        &mut svm,
        &account_pubkey,
        &payer.pubkey(),
        truncated_slot,
        &program_id,
    )
    .unwrap();

    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();
}

fn test_authentication_invalid_slothash(create_account_path: &str, auth_path: &str) {
    let payer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (mut svm, program_id) = initialize_svm(vec![payer.pubkey()]);

    let (_hash, truncated_slot) = get_valid_slothash(&svm);
    // Get the passkey account and instructions from our abstracted function
    let (account_pubkey, _public_key, instructions) = initialize_passkey_account(
        create_account_path,
        &payer.pubkey(),
        &truncated_slot,
        &program_id,
    )
    .unwrap();

    // Print the account information for debugging
    println!("Account to initialize: {:?}", account_pubkey);

    // Create and submit the transaction
    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();

    println!("Account created");
    // Verify the account was properly created
    let account = svm.get_account(&account_pubkey).unwrap();
    assert_eq!(account.data.len() > 0, true);

    let (_hash, truncated_slot) = get_expired_slothash(&svm);

    let instructions = authenticate_passkey_account(
        auth_path,
        &mut svm,
        &account_pubkey,
        &payer.pubkey(),
        truncated_slot,
        &program_id,
    )
    .unwrap();

    create_and_assert_svm_transaction(
        &mut svm,
        instructions,
        &payer.pubkey(),
        vec![&payer],
        Some(ExternalSignatureProgramError::ExpiredSlothash),
    )
    .unwrap();
}

fn test_authentication_invalid_truncated_slot(create_account_path: &str, auth_path: &str) {
    let payer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (mut svm, program_id) = initialize_svm(vec![payer.pubkey()]);

    let (_hash, truncated_slot) = get_valid_slothash(&svm);
    // Get the passkey account and instructions from our abstracted function
    let (account_pubkey, _public_key, instructions) = initialize_passkey_account(
        create_account_path,
        &payer.pubkey(),
        &truncated_slot,
        &program_id,
    )
    .unwrap();

    // Print the account information for debugging
    println!("Account to initialize: {:?}", account_pubkey);

    // Create and submit the transaction
    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();

    println!("Account created");
    // Verify the account was properly created
    let account = svm.get_account(&account_pubkey).unwrap();
    assert_eq!(account.data.len() > 0, true);

    let (_hash, mut truncated_slot) = get_valid_slothash(&svm);

    // This is invalid since we only expect 0 - 999 as a truncated slot
    truncated_slot.0 = 1000;
    let instructions = authenticate_passkey_account(
        auth_path,
        &mut svm,
        &account_pubkey,
        &payer.pubkey(),
        truncated_slot,
        &program_id,
    )
    .unwrap();

    create_and_assert_svm_transaction(
        &mut svm,
        instructions,
        &payer.pubkey(),
        vec![&payer],
        Some(ExternalSignatureProgramError::InvalidTruncatedSlot),
    )
    .unwrap();
}

#[cfg(test)]
mod test_authentication {
    use super::*;

    #[test]
    fn test_yubikey_authentication() {
        test_authentication_from_fixture(
            "tests/p256/fixtures/yubikey/creation.json",
            "tests/p256/fixtures/yubikey/authentication.json",
        );
    }

    #[test]
    fn test_chrome_authentication() {
        test_authentication_from_fixture(
            "tests/p256/fixtures/chrome/creation.json",
            "tests/p256/fixtures/chrome/authentication.json",
        );
    }

    #[test]
    fn test_one_password_authentication() {
        test_authentication_from_fixture(
            "tests/p256/fixtures/one-password/creation.json",
            "tests/p256/fixtures/one-password/authentication.json",
        );
    }

    #[test]
    fn test_ios_crossplatform_authentication() {
        test_authentication_from_fixture(
            "tests/p256/fixtures/ios-crossplatform/creation.json",
            "tests/p256/fixtures/ios-crossplatform/authentication.json",
        );
    }
    #[test]
    fn test_invalid_slothash() {
        test_authentication_invalid_slothash(
            "tests/p256/fixtures/chrome/creation.json",
            "tests/p256/fixtures/chrome/authentication.json",
        );
    }

    #[test]
    fn test_invalid_truncated_slot() {
        test_authentication_invalid_truncated_slot(
            "tests/p256/fixtures/chrome/creation.json",
            "tests/p256/fixtures/chrome/authentication.json",
        );
    }
}
