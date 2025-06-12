use num_enum::{IntoPrimitive, TryFromPrimitive};
use pinocchio::{instruction::Seed, pubkey::Pubkey, seeds};

#[derive(TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Debug, Clone, Copy)]
#[repr(u8)]
pub enum SignerExecutionScheme {
    /// Uses the derived execution account as the signer (legacy/default behavior)
    /// Useful for system operations like paying rent
    ExecutionAccount = 0,

    /// Uses the externally signed account directly as the signer
    /// More efficient for smart account operations
    ExternalAccount = 1,
}

/// Struct for easy access to the account that CPI's for instruction execution
pub struct ExecutionAccount {
    pub key: Pubkey,
    pub bump: u8,
    pub seeds: [Vec<u8>; 2],
}

impl<'a> ExecutionAccount {
    /// Returns the seeds for the execution account
    pub fn to_signer_seeds(&self) -> [Seed; 3] {
        let bump_ref = core::slice::from_ref(&self.bump);
        let seeds = seeds!(self.seeds[0].as_slice(), self.seeds[1].as_slice(), bump_ref);
        seeds
    }
}
