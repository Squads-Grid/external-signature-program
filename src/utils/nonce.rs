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
// Wrapper around a u16. Since we only need 150 slots of expiration we can just
// look at the last 4 digits of the slot height to get the correct slothash.
// This saves us the 30 extra bytes of having to submit a whole hash
pub struct TruncatedSlot(pub u16);

impl TruncatedSlot {
    /// Creates a new truncated slot from a slot
    pub fn new(untruncated_slot: u64) -> Result<Self, ProgramError> {
        let slot = untruncated_slot % 1000;
        Ok(Self(slot as u16))
    }

    /// Returns the difference between two truncated slots
    pub fn get_index_difference(&self, other: &Self) -> Result<u16, ProgramError> {
        // Handle wraparound case: if current slot is less than submitted slot,
        // it means we've wrapped around the 1000 boundary
        let diff = if self.0 >= other.0 {
            // Normal case: current slot >= submitted slot
            self.0
                .checked_sub(other.0)
                .ok_or(ExternalSignatureProgramError::InvalidTruncatedSlot)?
        } else {
            // Wraparound case: current slot < submitted slot
            // e.g., current=1, submitted=999 -> diff = 1 + (1000 - 999) = 2
            let wraparound_distance = 1000u16
                .checked_sub(other.0)
                .ok_or(ExternalSignatureProgramError::InvalidTruncatedSlot)?;

            self.0
                .checked_add(wraparound_distance)
                .ok_or(ExternalSignatureProgramError::InvalidTruncatedSlot)?
        };

        Ok(diff)
    }
}

pub struct NonceData<'a> {
    pub signer_key: &'a Pubkey,
    pub slothash: [u8; 32],
}

/// Validates a nonce signature
pub fn validate_nonce<'a>(
    slothashes_sysvar: SlotHashes<Ref<'a, [u8]>>,
    slot: &TruncatedSlot,
    nonce_signer: &'a AccountInfo,
) -> Result<NonceData<'a>, ProgramError> {
    // If the truncated slot is greater than 999, its automatically invalid.
    let Some(sanitized_truncated_slot) = (slot.0 < 1000).then_some(slot) else {
        return Err(ExternalSignatureProgramError::InvalidTruncatedSlot.into());
    };
    // Ensure the program isn't being called via CPI, since we need the signers
    // signature to be present in the runtimes signature cache to prevent replay
    let current_stack_height = get_stack_height();
    if current_stack_height > 1 {
        return Err(ExternalSignatureProgramError::CPINotAllowed.into());
    }

    // Check that the nonce signature is present
    if !nonce_signer.is_signer() {
        return Err(ExternalSignatureProgramError::MissingNonceSignature.into());
    }

    // Get current slothash and index difference to submitted slot
    let most_recent_slot_hash = slothashes_sysvar.get_slot_hash(0)?;

    let truncated_most_recent_slot = TruncatedSlot::new(most_recent_slot_hash.height)?;
    let index_difference =
        truncated_most_recent_slot.get_index_difference(&sanitized_truncated_slot)?;

    // Check that the slothash is not too old
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_slot_new() {
        // Test normal slot truncation
        assert_eq!(TruncatedSlot::new(1234567890).unwrap().0, 890);
        assert_eq!(TruncatedSlot::new(999).unwrap().0, 999);
        assert_eq!(TruncatedSlot::new(1000).unwrap().0, 0);
        assert_eq!(TruncatedSlot::new(1001).unwrap().0, 1);

        // Test the specific case from the issue
        assert_eq!(TruncatedSlot::new(349_863_001).unwrap().0, 1);
        assert_eq!(TruncatedSlot::new(349_862_999).unwrap().0, 999);
    }

    #[test]
    fn test_get_index_difference_normal_cases() {
        // Test normal cases where current >= submitted
        let current = TruncatedSlot(100);
        let submitted = TruncatedSlot(95);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 5);

        let current = TruncatedSlot(500);
        let submitted = TruncatedSlot(450);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 50);

        // Test same slot
        let current = TruncatedSlot(100);
        let submitted = TruncatedSlot(100);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 0);
    }

    #[test]
    fn test_get_index_difference_wraparound_cases() {
        // Test the specific case from the issue
        let current = TruncatedSlot(1); // slot 349,863,001 % 1000 = 1
        let submitted = TruncatedSlot(999); // slot 349,862,999 % 1000 = 999
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 2);

        // Test other wraparound cases
        let current = TruncatedSlot(0);
        let submitted = TruncatedSlot(999);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 1);

        let current = TruncatedSlot(5);
        let submitted = TruncatedSlot(998);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 7);

        let current = TruncatedSlot(10);
        let submitted = TruncatedSlot(990);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 20);
    }

    #[test]
    fn test_get_index_difference_edge_cases() {
        // Test maximum possible difference (should be less than 150 for valid usage)
        let current = TruncatedSlot(0);
        let submitted = TruncatedSlot(1);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 999);

        let current = TruncatedSlot(149);
        let submitted = TruncatedSlot(0);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 149);

        // Test boundary values
        let current = TruncatedSlot(999);
        let submitted = TruncatedSlot(0);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 999);

        let current = TruncatedSlot(999);
        let submitted = TruncatedSlot(999);
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 0);
    }

    #[test]
    fn test_get_index_difference_within_expiration_window() {
        // Test cases that should be within the 150 slot expiration window

        // Normal case: 149 slots ago
        let current = TruncatedSlot(149);
        let submitted = TruncatedSlot(0);
        let diff = current.get_index_difference(&submitted).unwrap();
        assert_eq!(diff, 149);
        assert!(diff < 150, "Should be within expiration window");

        // Wraparound case: 149 slots ago
        let current = TruncatedSlot(148);
        let submitted = TruncatedSlot(999);
        let diff = current.get_index_difference(&submitted).unwrap();
        assert_eq!(diff, 149);
        assert!(diff < 150, "Should be within expiration window");

        // Edge case: exactly at expiration boundary
        let current = TruncatedSlot(149);
        let submitted = TruncatedSlot(999);
        let diff = current.get_index_difference(&submitted).unwrap();
        assert_eq!(diff, 150);
        assert!(diff >= 150, "Should be at expiration boundary");
    }

    #[test]
    fn test_real_world_slot_scenarios() {
        // Test realistic slot progression scenarios

        // Scenario 1: Normal progression
        let slots = vec![
            349_862_995,
            349_862_996,
            349_862_997,
            349_862_998,
            349_862_999,
            349_863_000,
            349_863_001,
            349_863_002,
            349_863_003,
            349_863_004,
        ];

        let truncated_slots: Vec<TruncatedSlot> = slots
            .iter()
            .map(|&slot| TruncatedSlot::new(slot).unwrap())
            .collect();

        // Test the progression around the boundary
        assert_eq!(truncated_slots[4].0, 999); // 349_862_999 % 1000 = 999
        assert_eq!(truncated_slots[5].0, 0); // 349_863_000 % 1000 = 0
        assert_eq!(truncated_slots[6].0, 1); // 349_863_001 % 1000 = 1

        // Test differences across the boundary
        assert_eq!(
            truncated_slots[5]
                .get_index_difference(&truncated_slots[4])
                .unwrap(),
            1
        ); // 0 - 999 = 1
        assert_eq!(
            truncated_slots[6]
                .get_index_difference(&truncated_slots[4])
                .unwrap(),
            2
        ); // 1 - 999 = 2
        assert_eq!(
            truncated_slots[6]
                .get_index_difference(&truncated_slots[5])
                .unwrap(),
            1
        ); // 1 - 0 = 1
    }

    #[test]
    fn test_multiple_wraparounds() {
        // Test scenarios where we've wrapped around multiple times
        let current = TruncatedSlot(50);
        let submitted = TruncatedSlot(60); // This would be from a much earlier cycle

        // In this case, submitted slot appears to be "ahead" but is actually from a previous cycle
        // The difference should be 50 + (1000 - 60) = 990
        assert_eq!(current.get_index_difference(&submitted).unwrap(), 990);
    }
}
