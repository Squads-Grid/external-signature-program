use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction},
};

use super::SmallVec;
use crate::state::{ExecutionAccount, SignerExecutionScheme};

#[derive(BorshDeserialize, BorshSerialize)]
/// Compact representation of an instruction
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts_indices: SmallVec<u8, u8>,
    pub data: SmallVec<u16, u8>,
}

/// Creates account metas for instruction execution based on the execution account and scheme
pub fn create_instruction_execution_account_metas<'a>(
    instruction_execution_accounts: &'a [AccountInfo],
    execution_account: &ExecutionAccount,
    signer_execution_scheme: SignerExecutionScheme,
) -> Vec<AccountMeta<'a>> {
    instruction_execution_accounts
        .iter()
        .map(|account| match account.key() == &execution_account.key {
            true => match signer_execution_scheme {
                SignerExecutionScheme::ExternalAccount => {
                    // If we're directly signing with the external
                    // account, we want to do so with marked as non-mutable
                    AccountMeta::new(account.key(), false, true)
                }
                SignerExecutionScheme::ExecutionAccount => {
                    AccountMeta::new(account.key(), account.is_writable(), true)
                }
            },
            _ => {
                // All other accounts, use as they are passed in
                AccountMeta::new(account.key(), account.is_writable(), account.is_signer())
            }
        })
        .collect()
}
