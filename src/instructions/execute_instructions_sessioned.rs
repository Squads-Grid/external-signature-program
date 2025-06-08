use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::AccountInfo,
    cpi::slice_invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    instructions::CompiledInstruction,
    state::{ExecutionAccount, ExternallySignedAccount, SignatureScheme},
    state::{ExternallySignedAccountData, P256WebauthnAccountData},
    utils::SmallVec,
};

pub struct ExecuteInstructionsSessionedContext<'a, T: ExternallySignedAccountData> {
    pub external_account: Box<ExternallySignedAccount<'a, T>>,
    pub execution_account: ExecutionAccount<'a>,
    pub session_signer: &'a AccountInfo,
    pub instructions: Box<&'a [CompiledInstruction]>,
    pub instruction_execution_accounts: Box<&'a [AccountInfo]>,
    pub instruction_execution_account_metas: Box<Vec<AccountMeta<'a>>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExecutableInstructionSessionedArgs {
    pub signature_scheme: u8,
    pub instructions: SmallVec<u8, CompiledInstruction>,
}

impl<'a, T: ExternallySignedAccountData> ExecuteInstructionsSessionedContext<'a, T> {
    pub fn load(
        account_infos: &'a [AccountInfo],
        execution_args: &'a ExecutableInstructionSessionedArgs,
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

        let external_account = ExternallySignedAccount::<T>::new(external_account)?;
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

pub fn process_execute_instructions_sessioned(
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let args = ExecutableInstructionSessionedArgs::try_from_slice(data)
        .map_err(|_| ExternalSignatureProgramError::InvalidExecutionArgs)?;
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    let execution_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            ExecuteInstructionsSessionedContext::<P256WebauthnAccountData>::load(accounts, &args)?
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
