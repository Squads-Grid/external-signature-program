use crate::{
    state::{ExecutionAccount, ExternallySignedAccount, SignatureScheme, SignerExecutionScheme},
    utils::{
        create_instruction_execution_account_metas, hash, validate_nonce, CompiledInstruction, NonceData, SlotHashes, TruncatedSlot
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    cpi::slice_invoke_signed,
    instruction::{AccountMeta, Instruction, Signer},
    program_error::ProgramError,
    sysvars::instructions::Instructions,
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{ExternallySignedAccountData, P256WebauthnAccountData},
    utils::SmallVec,
};
// Raw arguments for execution instruction data
#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExecutableInstructionArgs {
    pub signature_scheme: u8,
    pub signer_execution_scheme: u8,
    pub slothash: TruncatedSlot,
    pub extra_verification_data: SmallVec<u8, u8>,
    pub instructions: SmallVec<u8, CompiledInstruction>,
}

// Sanitized and checked accounts for execution
pub struct ExecuteInstructionsAccounts<'a, T: ExternallySignedAccountData> {
    // [MUT]
    pub externally_signed_account: ExternallySignedAccount<'a, T>,
    pub instructions_sysvar: Instructions<Ref<'a, [u8]>>,
    // [SIGNER]
    pub nonce_signer: &'a AccountInfo,
    pub instruction_execution_accounts: &'a [AccountInfo],
}

// Sanitized and checked context for execution
pub struct ExecuteInstructionsContext<'a, T: ExternallySignedAccountData> {
    pub nonce_data: NonceData<'a>,
    pub execution_account: ExecutionAccount,
    pub signature_scheme_specific_verification_data: T::ParsedVerificationData,
    pub accounts: ExecuteInstructionsAccounts<'a, T>,
    pub instructions: &'a [CompiledInstruction],
    pub instruction_execution_account_metas: Vec<AccountMeta<'a>>,
}

impl<'a, T: ExternallySignedAccountData> ExecuteInstructionsContext<'a, T> {
    // Sanitizes, checks and loads the context from the account infos and args
    pub fn load(
        account_infos: &'a [AccountInfo],
        execution_args: &'a ExecutableInstructionArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (
            externally_signed_account,
            instructions_sysvar,
            slothashes_sysvar,
            nonce_signer,
            instruction_execution_accounts,
        ) = if let [external_account, instructions_sysvar, slothashes_sysvar, nonce_signer, instruction_execution_accounts @ ..] =
            account_infos
        {
            (
                external_account,
                instructions_sysvar,
                slothashes_sysvar,
                nonce_signer,
                instruction_execution_accounts,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        // Parse the signature scheme specific verification data
        let args = T::RawVerificationData::try_from_slice(
            &execution_args.extra_verification_data.as_slice(),
        )
        .map_err(|_| ExternalSignatureProgramError::InvalidExtraVerificationDataArgs)?;
        let parsed_verification_data = T::ParsedVerificationData::try_from(args)?;

        // Load and check the relevant accounts
        let externally_signed_account =
            ExternallySignedAccount::<T>::load(externally_signed_account)?;
        externally_signed_account.check_account(&parsed_verification_data)?;
        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;

        // Validate the nonce
        let nonce_data = validate_nonce(slothashes_sysvar, &execution_args.slothash, nonce_signer)?;

        // Get the execution account for instruction execution based on the signer execution scheme
        let signer_execution_scheme =
            SignerExecutionScheme::try_from_primitive(execution_args.signer_execution_scheme)
                .map_err(|_| ExternalSignatureProgramError::InvalidSignerExecutionScheme)?;
        let execution_account =
            externally_signed_account.get_execution_account(signer_execution_scheme)?;

        // Create instruction execution account metas using the utility function
        let instruction_execution_account_metas = create_instruction_execution_account_metas(
            instruction_execution_accounts,
            &execution_account,
            signer_execution_scheme,
        );

        Ok(Box::new(Self {
            accounts: ExecuteInstructionsAccounts {
                externally_signed_account,
                instructions_sysvar,
                nonce_signer,
                instruction_execution_accounts,
            },
            execution_account,
            signature_scheme_specific_verification_data: parsed_verification_data,
            instruction_execution_account_metas,
            nonce_data,
            instructions: execution_args.instructions.as_slice(),
        }))
    }

    // Gets the instruction payload hash
    pub fn get_instruction_payload_hash(&self) -> [u8; 32] {
        let mut instruction_payload: Vec<u8> = Vec::new();
        // Nonce data
        instruction_payload.extend_from_slice(self.nonce_data.slothash.as_slice());
        instruction_payload.extend_from_slice(self.nonce_data.signer_key.as_ref());
        instruction_payload.extend_from_slice(b"execute_instructions");

        // Number of instruction execution accounts
        instruction_payload.push(self.accounts.instruction_execution_accounts.len() as u8);
        // Build the instruction execution accounts and their metas as they were
        // passed in
        self.accounts
            .instruction_execution_accounts
            .iter()
            .for_each(|account| {
                instruction_payload.extend_from_slice(account.key().as_ref());
                instruction_payload.push(account.is_signer() as u8);
                instruction_payload.push(account.is_writable() as u8);
            });

        // Build the instructions
        instruction_payload.push(self.instructions.len() as u8);
        for instruction in self.instructions.iter() {
            instruction.serialize(&mut instruction_payload).unwrap();
        }
        hash(&instruction_payload)
    }
}

// Processes the execute instructions instruction
pub fn process_execute_instructions(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Parse the execution args
    let args = ExecutableInstructionArgs::try_from_slice(data)
        .map_err(|_| ExternalSignatureProgramError::InvalidExecutionArgs)?;
    // Parse the signature scheme
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;

    // Load the execution context based on the signature scheme
    let mut execution_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            ExecuteInstructionsContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

    // Get the instruction execution payload hash
    let instruction_execution_hash = execution_context.get_instruction_payload_hash();

    // Verify the instruction payload
    execution_context
        .accounts
        .externally_signed_account
        .verify_payload(
            &execution_context.accounts.instructions_sysvar,
            &execution_context.signature_scheme_specific_verification_data,
            &instruction_execution_hash,
        )?;

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

        // Build the instruction to invoke
        let instruction_to_invoke = Instruction {
            program_id: execution_context.accounts.instruction_execution_accounts
                [instruction.program_id_index as usize]
                .key(),
            data: &instruction.data.as_slice(),
            accounts: &account_metas,
        };

        // prevent against re-entrancy
        assert_ne!(instruction_to_invoke.program_id, &crate::ID);

        // Invoke the instruction
        slice_invoke_signed(
            &instruction_to_invoke,
            filtered_account_infos.as_slice(),
            &[Signer::from(
                &execution_context.execution_account.to_signer_seeds(),
            )],
        )?;

        // Clear the containers for next iteration
        account_metas.clear();
        account_info_indices.clear();
    }
    Ok(())
}
