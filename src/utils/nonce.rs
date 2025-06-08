use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    errors::ExternalSignatureProgramError,
    utils::{get_stack_height, SlotHashes},
};

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct TruncatedSlot(pub u32);

impl TruncatedSlot {
    pub fn new(untruncated_slot: u64) -> Result<Self, ProgramError> {
        // We only expect truncated slots to be 0 - 999
        if untruncated_slot > 999 {
            return Err(ExternalSignatureProgramError::InvalidTruncatedSlot.into());
        }
        let slot = untruncated_slot % 1000;
        Ok(Self(slot as u32))
    }

    pub fn get_index_difference(&self, other: &Self) -> Result<u32, ProgramError> {
        // Truncated slot should never be greater than a current slot
        self.0
            .checked_sub(other.0)
            .ok_or(ExternalSignatureProgramError::InvalidTruncatedSlot.into())
    }
}

pub struct NonceData<'a> {
    pub signer_key: &'a Pubkey,
    pub slothash: [u8; 32],
}

pub fn validate_nonce<'a>(
    slothashes_sysvar: SlotHashes<Ref<'a, [u8]>>,
    slot: &TruncatedSlot,
    nonce_signer: &'a AccountInfo,
) -> Result<NonceData<'a>, ProgramError> {
    // Ensure the program isn't being called via CPI
    let current_stack_height = get_stack_height();
    if current_stack_height > 1 {
        return Err(ExternalSignatureProgramError::CPINotAllowed.into());
    }

    // Check that the nonce signature is present
    if !nonce_signer.is_signer() {
        return Err(ExternalSignatureProgramError::MissingNonceSignature.into());
    }

    // Check that the slothash is not too old
    let most_recent_slot_hash = slothashes_sysvar.get_slot_hash(0)?;
    let truncated_most_recent_slot = TruncatedSlot::new(most_recent_slot_hash.height)?;
    let index_difference = truncated_most_recent_slot.get_index_difference(&slot)?;

    if index_difference >= 150 {
        return Err(ExternalSignatureProgramError::ExpiredSlothash.into());
    }

    // Get the slot hash at the index difference
    let slot_hash = slothashes_sysvar.get_slot_hash(index_difference as usize)?;

    Ok(NonceData {
        signer_key: nonce_signer.key(),
        slothash: slot_hash.hash,
    })
}
