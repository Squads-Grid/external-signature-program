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
    state::{
        ExecutionAccount, ExternallySignedAccount, ExternallySignedAccountData,
        P256WebauthnAccountData, SignatureScheme, SignerExecutionScheme,
    },
    utils::{create_instruction_execution_account_metas, CompiledInstruction, SmallVec},
};

// Raw arguments for execution instruction data
#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExecutableInstructionSessionedArgs {
    pub signature_scheme: u8,
    pub signer_execution_scheme: u8,
    pub instructions: SmallVec<u8, CompiledInstruction>,
}

// Sanitized and checked accounts for execution
pub struct ExecuteInstructionsSessionedAccounts<'a, T: ExternallySignedAccountData> {
    // [MUT]
    pub externally_signed_account: ExternallySignedAccount<'a, T>,
    // [SIGNER]
    pub session_signer: &'a AccountInfo,
    pub instruction_execution_accounts: &'a [AccountInfo],
}

// Sanitized and checked context for execution
pub struct ExecuteInstructionsSessionedContext<'a, T: ExternallySignedAccountData> {
    pub accounts: ExecuteInstructionsSessionedAccounts<'a, T>,
    pub execution_account: ExecutionAccount,
    pub instructions: &'a [CompiledInstruction],
    pub instruction_execution_account_metas: Vec<AccountMeta<'a>>,
}

impl<'a, T: ExternallySignedAccountData> ExecuteInstructionsSessionedContext<'a, T> {
    // Sanitizes, checks and loads the context from the account infos and args
    pub fn load(
        account_infos: &'a [AccountInfo],
        execution_args: &'a ExecutableInstructionSessionedArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (externally_signed_account, session_signer, instruction_execution_accounts) = if let [externally_signed_account, session_signer, instruction_execution_accounts @ ..] =
            account_infos
        {
            (
                externally_signed_account,
                session_signer,
                instruction_execution_accounts,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Load and check the relevant accounts
        let externally_signed_account =
            ExternallySignedAccount::<T>::load(externally_signed_account)?;
        externally_signed_account.is_valid_session_key(session_signer)?;

        // Get the executing account based on the signer execution scheme
        let signer_execution_scheme =
            SignerExecutionScheme::try_from_primitive(execution_args.signer_execution_scheme)
                .map_err(|_| ExternalSignatureProgramError::InvalidSignerExecutionScheme)?;
        let executing_account =
            externally_signed_account.get_execution_account(signer_execution_scheme)?;

        // Build the instruction execution account metas
        let instruction_execution_account_metas = create_instruction_execution_account_metas(
            instruction_execution_accounts,
            &executing_account,
            signer_execution_scheme,
        );

        Ok(Box::new(Self {
            accounts: ExecuteInstructionsSessionedAccounts {
                externally_signed_account,
                session_signer,
                instruction_execution_accounts,
            },
            execution_account: executing_account,
            instructions: execution_args.instructions.as_slice(),
            instruction_execution_account_metas,
        }))
    }
}

/// Processes the execute instructions sessioned instruction
pub fn process_execute_instructions_sessioned(
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Parse the execution args
    let args = ExecutableInstructionSessionedArgs::try_from_slice(data)
        .map_err(|_| ExternalSignatureProgramError::InvalidExecutionArgs)?;
    // Parse the signature scheme
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    // Load the execution context based on the signature scheme
    let execution_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            ExecuteInstructionsSessionedContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

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
            .map(|&index| {
                &execution_context.accounts.instruction_execution_accounts[index as usize]
            })
            .collect();

        let instruction_to_invoke = Instruction {
            program_id: execution_context.accounts.instruction_execution_accounts
                [instruction.program_id_index as usize]
                .key(),
            data: &instruction.data.as_slice(),
            accounts: &account_metas,
        };

        // prevent against re-entrancy
        assert_ne!(instruction_to_invoke.program_id, &crate::ID);

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
