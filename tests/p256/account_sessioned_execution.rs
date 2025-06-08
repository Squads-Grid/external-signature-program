use std::time::{SystemTime, UNIX_EPOCH};

use external_signature_program::errors::ExternalSignatureProgramError;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_program::clock::Clock;
use solana_pubkey::Pubkey;
use solana_signer::{EncodableKey, Signer};

use crate::svm::create_and_send_svm_transaction;

use super::{
    execute_sessioned_instructions::execute_sessioned_instructions,
    svm::create_and_assert_svm_transaction,
};

fn test_sessioned_execution_from_fixture(
    payer: &Keypair,
    mut svm: &mut LiteSVM,
    external_account_pubkey: &Pubkey,
    session_key: &Keypair,
    program_id: &Pubkey,
) {
    let instructions = execute_sessioned_instructions(
        session_key,
        &mut svm,
        &external_account_pubkey,
        &program_id,
    )
    .unwrap();

    create_and_send_svm_transaction(
        &mut svm,
        instructions.clone(),
        &payer.pubkey(),
        vec![&payer, session_key],
    )
    .unwrap();

    // Warp forwards by 1000 seconds
    let mut clock = svm.get_sysvar::<Clock>();
    let new_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1000;
    clock.unix_timestamp = new_timestamp as i64;
    svm.set_sysvar(&clock);

    // Expire the blockhash so we can process another transaction
    svm.expire_blockhash();
    // Expect sending the transaction again to fail due to an expired session
    // key "ExpiredSessionKey"
    create_and_assert_svm_transaction(
        &mut svm,
        instructions,
        &payer.pubkey(),
        vec![&payer, session_key],
        Some(ExternalSignatureProgramError::SessionKeyExpired),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::account_session_authentication::test_session_authentication_from_fixture;

    use super::*;

    #[test]
    fn test_chrome() {
        let payer = Keypair::read_from_file(
            "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
        )
        .unwrap();
        let session_key = Keypair::read_from_file(
            "tests/p256/keypairs/sesfSDjioiWGpxqSoHSfMGrQe3wAyEBDSAL3niVecdC.json",
        )
        .unwrap();
        let program_id = Pubkey::new_from_array(external_signature_program::ID);
        let mut response = test_session_authentication_from_fixture(
            &payer,
            "tests/p256/fixtures/chrome/creation.json",
            "tests/p256/fixtures/chrome/session_key_authentication.json",
        )
        .unwrap();

        test_sessioned_execution_from_fixture(
            &payer,
            &mut response.svm,
            &response.account_pubkey,
            &session_key,
            &program_id,
        );
    }
}
