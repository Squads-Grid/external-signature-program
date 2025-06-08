use bincode::serialize;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::pubkey::Pubkey;
use solana_signer::{EncodableKey, Signer};
use solana_transaction::Transaction;

use crate::utils::instruction_and_payload_generation::create_memo_instruction;
use crate::utils::instruction_and_payload_generation::create_system_transfer_instruction;

#[test]
fn test_non_wrapped_execution() {
    let mut svm = LiteSVM::new().with_sigverify(false);
    println!("svm: {:#?}", svm.get_sigverify());
    let signer_keypair = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    svm.airdrop(&signer_keypair.pubkey(), 1_000_000_000)
        .unwrap();
    let memo_instruction = create_memo_instruction();
    let random_account = Pubkey::new_unique();
    svm.airdrop(&random_account, 1000000000).unwrap();
    let mut system_transfer_instruction = create_system_transfer_instruction(random_account);
    system_transfer_instruction.accounts[0].is_signer = true;
    let blockhash = svm.latest_blockhash();

    let message = Message::new_with_blockhash(
        &[memo_instruction, system_transfer_instruction],
        Some(&signer_keypair.pubkey()),
        &blockhash,
    );

    let tx = Transaction::new_unsigned(message);
    let serialized_tx = serialize(&tx).unwrap();
    let result = svm.with_sigverify(false).send_transaction(tx);
    assert!(
        result.is_ok(),
        "Failed to simulate transaction: {:#?}",
        result
    );
    println!("Result: {:#?}", result);
    println!("Serialized tx len: {:#?}", serialized_tx.len());
}
