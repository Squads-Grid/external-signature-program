use borsh::{BorshDeserialize, BorshSerialize};

use crate::utils::SmallVec;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts_indices: SmallVec<u8, u8>,
    pub data: SmallVec<u16, u8>,
}