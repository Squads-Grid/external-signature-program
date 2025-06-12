use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    p256::utils::{
        initialization::initialize_passkey_account,
        svm::{create_and_send_svm_transaction, get_valid_slothash, initialize_svm},
    },
    refresh_session_key::{refresh_session_key, TESTING_SESSION_KEY},
};
use external_signature_program::state::P256WebauthnAccountData;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::{EncodableKey, Signer};

pub struct AccountSessionAuthentication {
    pub svm: LiteSVM,
    pub account_pubkey: Pubkey,
    pub passkey_pubkey: [u8; 33],
}
pub fn test_session_authentication_from_fixture(
    payer: &Keypair,
    create_account_path: &str,
    refresh_session_key_path: &str,
) -> Result<AccountSessionAuthentication, Box<dyn std::error::Error>> {
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

    println!(
        "Session Key Expiration: {:#?}",
        account_data.session_key.expiration
    );
    // get the current system time in seconds
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expected_expiration = current_time + 900;
    assert_eq!(account_data.session_key.expiration, expected_expiration);
    assert_eq!(account_data.session_key.key, TESTING_SESSION_KEY.key);

    Ok(AccountSessionAuthentication {
        svm,
        account_pubkey,
        passkey_pubkey: account_data.public_key.to_bytes(),
    })
}

#[cfg(test)]
mod test_authentication {
    use super::*;

    // #[test]
    fn test_yubikey_authentication() {
        let payer = Keypair::read_from_file(
            "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
        )
        .unwrap();
        let _ = test_session_authentication_from_fixture(
            &payer,
            "tests/p256/fixtures/yubikey/creation.json",
            "tests/p256/fixtures/yubikey/authentication.json",
        );
    }

    #[test]
    fn test_chrome_authentication() {
        let payer = Keypair::read_from_file(
            "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
        )
        .unwrap();
        let _ = test_session_authentication_from_fixture(
            &payer,
            "tests/p256/fixtures/chrome/creation.json",
            "tests/p256/fixtures/chrome/session_key_authentication.json",
        );
    }

    // #[test]
    fn test_one_password_authentication() {
        let payer = Keypair::read_from_file(
            "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
        )
        .unwrap();
        let _ = test_session_authentication_from_fixture(
            &payer,
            "tests/p256/fixtures/one-password/creation.json",
            "tests/p256/fixtures/one-password/session_key_authentication.json",
        );
    }
}
