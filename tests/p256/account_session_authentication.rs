use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    p256::utils::{
        authentication::authenticate_passkey_account,
        initialization::initialize_passkey_account,
        svm::{create_and_send_svm_transaction, get_valid_slothash, initialize_svm},
    },
    refresh_session_key::{refresh_session_key, TESTING_SESSION_KEY},
};
use external_signature_program::state::P256WebauthnAccountData;
use solana_keypair::Keypair;
use solana_signer::{EncodableKey, Signer};

fn test_authentication_from_fixture(create_account_path: &str, refresh_session_key_path: &str) {
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

    let instructions = refresh_session_key(
        refresh_session_key_path,
        &mut svm,
        &account_pubkey,
        &payer.pubkey(),
        truncated_slot,
        &program_id,
    )
    .unwrap();

    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();

    let account = svm.get_account(&account_pubkey).unwrap();
    let account_data: &P256WebauthnAccountData = bytemuck::from_bytes(&account.data);

    println!("account_data: {:#?}", account_data.session_key.expiration);
    // get the current system time in seconds
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expected_expiration = current_time + 900;
    assert_eq!(account_data.session_key.expiration, expected_expiration);
    assert_eq!(account_data.session_key.key, TESTING_SESSION_KEY.key);
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
            "tests/p256/fixtures/chrome/session_key_authentication.json",
        );
    }

    #[test]
    fn test_one_password_authentication() {
        test_authentication_from_fixture(
            "tests/p256/fixtures/one-password/creation.json",
            "tests/p256/fixtures/one-password/authentication.json",
        );
    }
}
