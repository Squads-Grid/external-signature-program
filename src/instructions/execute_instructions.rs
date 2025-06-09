use crate::{
    state::{
        AccountSeedsTrait, ExecutionAccount, ExternallySignedAccount, SignatureScheme,
        SignerExecutionScheme,
    },
    utils::{
        nonce::{validate_nonce, TruncatedSlot},
        sha256::hash,
        SlotHashes,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use num_enum::TryFromPrimitive;
use pinocchio::{
    account_info::{AccountInfo, Ref},
    cpi::slice_invoke_signed,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program_error::ProgramError,
    seeds,
    sysvars::instructions::Instructions,
    ProgramResult,
};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{ExternallySignedAccountData, P256WebauthnAccountData},
    utils::SmallVec,
};

pub struct ExecuteInstructionsContext<'a, T: ExternallySignedAccountData> {
    pub external_account: Box<ExternallySignedAccount<'a, T>>,
    pub execution_account: ExecutionAccount<'a>,
    pub signature_scheme_specific_verification_data: T::ParsedVerificationData,
    pub instructions_sysvar_account: Box<Instructions<Ref<'a, [u8]>>>,
    pub slothash: [u8; 32],
    pub signer_account: &'a AccountInfo,
    pub instructions: Box<&'a [CompiledInstruction]>,
    pub instruction_execution_accounts: Box<&'a [AccountInfo]>,
    pub instruction_execution_account_metas: Box<Vec<AccountMeta<'a>>>,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ExecutableInstructionArgs {
    pub signature_scheme: u8,
    pub slothash: TruncatedSlot,
    pub extra_verification_data: SmallVec<u8, u8>,
    pub instructions: SmallVec<u8, CompiledInstruction>,
    pub signer_execution_scheme: u8,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts_indices: SmallVec<u8, u8>,
    pub data: SmallVec<u16, u8>,
}

impl<'a, T: ExternallySignedAccountData> ExecuteInstructionsContext<'a, T> {
    pub fn load(
        account_infos: &'a [AccountInfo],
        execution_args: &'a ExecutableInstructionArgs,
    ) -> Result<Box<Self>, ProgramError> {
        let (
            external_account,
            instructions_sysvar,
            slothashes_sysvar,
            signer_account,
            instruction_execution_accounts,
        ) = if let [external_account, instructions_sysvar, slothashes_sysvar, signer_account, instruction_execution_accounts @ ..] =
            account_infos
        {
            (
                external_account,
                instructions_sysvar,
                slothashes_sysvar,
                signer_account,
                instruction_execution_accounts,
            )
        } else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        let signer_execution_scheme =
            SignerExecutionScheme::try_from_primitive(execution_args.signer_execution_scheme)
                .map_err(|_| ExternalSignatureProgramError::InvalidSignerExecutionScheme)?;
        let external_account = ExternallySignedAccount::<T>::new(external_account)?;
        let execution_account = external_account.get_execution_account(signer_execution_scheme)?;
        let args = T::RawVerificationData::try_from_slice(
            &execution_args.extra_verification_data.as_slice(),
        )
        .map_err(|_| ExternalSignatureProgramError::InvalidExtraVerificationDataArgs)?;
        let parsed_verification_data = T::ParsedVerificationData::from(args);
        external_account.check_account(&parsed_verification_data)?;

        let instructions_sysvar = Instructions::try_from(instructions_sysvar)?;
        let slothashes_sysvar = SlotHashes::try_from(slothashes_sysvar)?;

        let nonce_data =
            validate_nonce(slothashes_sysvar, &execution_args.slothash, signer_account)?;

        let signer_execution_account = match signer_execution_scheme {
            SignerExecutionScheme::ExternalAccount => external_account.account_info,
            SignerExecutionScheme::ExecutionAccount => execution_account.account_info,
        };

        let execution_account_seeds = external_account.derive_existing_account()?;
        let seeds = execution_account_seeds.seeds();
        let external_account_signer_seeds =
            seeds.iter().map(|s| Seed::from(*s)).collect::<Vec<Seed>>();
        let execution_account_signer_seeds = execution_account.to_signer_seeds();

        // validate the signer execution scheme
        let signer: [Signer; 1] = match signer_execution_scheme {
            SignerExecutionScheme::ExternalAccount => {
                if !external_account.account_info.is_signer() {
                    return Err(
                        ExternalSignatureProgramError::SignerExecutionAccountNotASigner.into(),
                    );
                }

                let signer = [Signer::from(external_account_signer_seeds.as_slice())];

                signer
            }
            SignerExecutionScheme::ExecutionAccount => {
                let signer = [Signer::from(execution_account_signer_seeds.as_slice())];

                signer
            }
        };

        let instruction_execution_account_metas = instruction_execution_accounts
            .iter()
            .map(
                |account| match account.key() == signer_execution_account.key() {
                    // The execution account needs to be set to be a signer for the
                    // later instruction execution
                    true => match signer_execution_scheme {
                        SignerExecutionScheme::ExternalAccount => {
                            AccountMeta::new(account.key(), false, true)
                        }
                        SignerExecutionScheme::ExecutionAccount => {
                            AccountMeta::new(account.key(), account.is_writable(), true)
                        }
                    },
                    _ => {
                        AccountMeta::new(account.key(), account.is_writable(), account.is_signer())
                    }
                },
            )
            .collect();

        Ok(Box::new(Self {
            external_account: Box::new(external_account),
            execution_account,
            signature_scheme_specific_verification_data: parsed_verification_data,
            instructions_sysvar_account: Box::new(instructions_sysvar),
            signer_account,
            instruction_execution_accounts: Box::new(instruction_execution_accounts),
            instruction_execution_account_metas: Box::new(instruction_execution_account_metas),
            slothash: nonce_data.slothash,
            instructions: Box::new(execution_args.instructions.as_slice()),
        }))
    }

    pub fn get_instruction_payload_hash(&self) -> [u8; 32] {
        let mut instruction_payload: Vec<u8> = Vec::new();
        instruction_payload.extend_from_slice(self.slothash.as_slice());
        instruction_payload.extend_from_slice(self.signer_account.key().as_ref());

        self.instruction_execution_accounts
            .iter()
            .for_each(|account| {
                instruction_payload.extend_from_slice(account.key().as_ref());
                instruction_payload.push(account.is_signer() as u8);
                instruction_payload.push(account.is_writable() as u8);
            });
        instruction_payload.push(self.instructions.len() as u8);
        for instruction in self.instructions.iter() {
            instruction.serialize(&mut instruction_payload).unwrap();
        }
        //self.instructions.serialize(&mut instruction_payload).unwrap();
        hash(&instruction_payload)
    }
}

pub fn process_execute_instructions(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let args = ExecutableInstructionArgs::try_from_slice(data)
        .map_err(|_| ExternalSignatureProgramError::InvalidExecutionArgs)?;
    let signature_scheme = SignatureScheme::try_from_primitive(args.signature_scheme)
        .map_err(|_| ExternalSignatureProgramError::InvalidSignatureScheme)?;
    let signer_execution_type =
        SignerExecutionScheme::try_from_primitive(args.signer_execution_scheme)
            .map_err(|_| ExternalSignatureProgramError::InvalidSignerExecutionScheme)?;

    let mut execution_context = match signature_scheme {
        SignatureScheme::P256Webauthn => {
            ExecuteInstructionsContext::<P256WebauthnAccountData>::load(accounts, &args)?
        }
    };

    let instruction_execution_hash = execution_context.get_instruction_payload_hash();

    execution_context.external_account.verify_payload(
        &execution_context.instructions_sysvar_account,
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
