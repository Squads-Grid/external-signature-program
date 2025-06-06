use std::cmp::max;

use crate::{
    checks::nonce::{validate_nonce, TruncatedSlot},
    errors::assert_with_msg,
    signatures::{
        reconstruct_client_data_json, AuthDataParser, AuthType, ClientDataJsonReconstructionParams,
    },
    state::{ExecutionAccount, ExternallyOwnedAccount},
    utils::{hashv, sha256::hash, SlotHash, SlotHashes},
};
use base64::{engine::general_purpose, Engine};
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    cpi::slice_invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    log::sol_log_compute_units,
    msg,
    program_error::ProgramError,
    syscalls::sol_remaining_compute_units,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    signatures::SignatureScheme,
    state::{ExternallyOwnedAccountData, P256WebauthnAccountData},
    utils::SmallVec,
};

// TODO: Rename
pub struct ExecuteInstructionsContext<'a, T: ExternallyOwnedAccountData> {
    pub external_account: Box<ExternallyOwnedAccount<'a, T>>,
    pub execution_account: ExecutionAccount<'a>,
    pub session_signer: &'a AccountInfo,
    pub instructions: Box<&'a [CompiledInstruction]>,
    pub instruction_execution_accounts: Box<&'a [AccountInfo]>,
    pub instruction_execution_account_metas: Box<Vec<AccountMeta<'a>>>,
}
// TODO: Rename
#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExecutableInstructionArgs {
    pub signature_scheme: u8,
    pub instructions: SmallVec<u8, CompiledInstruction>,
}

// TODO: Put in shared file
#[derive(BorshDeserialize, BorshSerialize)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts_indices: SmallVec<u8, u8>,
    pub data: SmallVec<u16, u8>,
}

impl<'a, T: ExternallyOwnedAccountData> ExecuteInstructionsContext<'a, T> {
    pub fn load(
        account_infos: &'a [AccountInfo],
        execution_args: &'a ExecutableInstructionArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (external_account, session_signer, instruction_execution_accounts) = if let [external_account, session_signer, instruction_execution_accounts @ ..] =
            account_infos
        {
            (
                external_account,
                session_signer,
                instruction_execution_accounts,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        let external_account = ExternallyOwnedAccount::<T>::new(external_account)?;
        let external_execution_account = external_account.get_execution_account();

        if !session_signer.is_signer() {
            return Err(ExternalSignatureProgramError::SessionSignerNotASigner.into());
        }

        let instruction_execution_account_metas = instruction_execution_accounts
            .iter()
            .map(
                |account| match account.key() == &external_execution_account.key {
                    // The execution account needs to be set to be a signer for the
                    // later instruction execution
                    true => AccountMeta::new(account.key(), account.is_writable(), true),
                    _ => {
                        AccountMeta::new(account.key(), account.is_writable(), account.is_signer())
                    }
                },
            )
            .collect();

        Ok(Box::new(Self {
            external_account: Box::new(external_account),
            execution_account: external_execution_account,
            session_signer,
            instruction_execution_accounts: Box::new(instruction_execution_accounts),
            instruction_execution_account_metas: Box::new(instruction_execution_account_metas),
            instructions: Box::new(execution_args.instructions.as_slice()),
        }))
    }
}

pub fn process_execute_instructions(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let args = ExecutableInstructionArgs::try_from_slice(data)
        .map_err(|_| ExternalSignatureProgramError::InvalidExecutionArgs)?;
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    let execution_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            ExecuteInstructionsContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

    // Check that the session is valid
    execution_context
        .external_account
        .is_valid_session_key(execution_context.session_signer.key())?;

    // Initialize containers for both data structures
    let mut account_metas = Vec::with_capacity(256);
    let mut account_info_indices = Vec::with_capacity(64);

    for instruction in args.instructions.iter() {
        let mut seen_indices = [false; 64]; // A maximum of 64 account infos are allowed by the runtime

        // Build AccountMeta vector and collect unique indices in one pass
        for &index in instruction.accounts_indices.iter() {
            account_metas.push(
                execution_context.instruction_execution_account_metas[index as usize].clone(),
            );
            // Track unique indices for AccountInfo references
            if !seen_indices[index as usize] {
                seen_indices[index as usize] = true;
                account_info_indices.push(index);
            }
        }

        // Now create the filtered account infos using the unique indices
        let filtered_account_infos: Vec<&AccountInfo> = account_info_indices
            .iter()
            .map(|&index| &execution_context.instruction_execution_accounts[index as usize])
            .collect();

        let instruction_to_invoke = Instruction {
            program_id: execution_context.instruction_execution_accounts
                [instruction.program_id_index as usize]
                .key(),
            data: &instruction.data.as_slice(),
            accounts: &account_metas,
        };

        slice_invoke_signed(
            &instruction_to_invoke,
            filtered_account_infos.as_slice(),
            &[Signer::from(
                &execution_context.execution_account.to_signer_seeds(),
            )],
        )?;

        account_metas.clear();
        account_info_indices.clear();
    }
    Ok(())
}
