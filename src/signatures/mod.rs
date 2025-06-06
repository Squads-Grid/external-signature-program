pub mod p256_webauthn;

pub use p256_webauthn::*;

/// Represents the different signature schemes supported by the program
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
#[repr(u8)]
pub enum SignatureScheme {
    /// Webauthn P-256 (secp256r1) curve
    P256Webauthn = 0,
}
