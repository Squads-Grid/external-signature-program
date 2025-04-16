use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use pinocchio::program_error::ProgramError;

pub mod p256_webauthn;

pub use p256_webauthn::*;


/// Represents the different signature schemes supported by the program
#[derive(TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Webauthn P-256 (secp256r1) curve
    P256Webauthn = 0,
}

