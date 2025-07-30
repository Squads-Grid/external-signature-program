use std::{any::type_name, panic::Location};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use pinocchio::{program_error::ProgramError, ProgramResult};
use pinocchio_log::log;
use thiserror::Error;

#[repr(u32)]
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
pub enum ExternalSignatureProgramError {
    // Nonce Related Errors
    #[error("Invalid slothash index")]
    InvalidSlothashIndex,
    #[error("Invalid truncated slot")]
    InvalidTruncatedSlot,
    #[error("Expired slothash")]
    ExpiredSlothash,
    #[error("Missing nonce signature")]
    MissingNonceSignature,
    #[error("CPI not allowed")]
    CPINotAllowed,

    /// Instrospection Related Errors
    #[error("Invalid instruction sysvar account")]
    InvalidInstructionSysvarAccount,
    #[error("Invalid precompile id")]
    InvalidPrecompileId,
    #[error("Invalid number of precompile signatures")]
    InvalidNumPrecompileSignatures,
    #[error("Invalid signature index")]
    InvalidSignatureIndex,
    #[error("Invalid signature offset")]
    InvalidSignatureOffset,

    /// Account Ser/Des Related Errors
    #[error("Error initializing header")]
    ErrorInitializingHeader,
    #[error("Error deserializing header")]
    ErrorDeserializingHeader,
    #[error("Error initializing account data")]
    ErrorInitializingAccountData,
    #[error("Error deserializing account data")]
    ErrorDeserializingAccountData,

    /// Execute Instructions Related Errors
    #[error("Invalid extra verification data args")]
    InvalidExtraVerificationDataArgs,
    #[error("Invalid execution args")]
    InvalidExecutionArgs,
    #[error("Session signer is not a signer")]
    SessionSignerNotASigner,
    #[error("Invalid session key")]
    InvalidSessionKey,
    #[error("Session key expired")]
    SessionKeyExpired,
    #[error("Invalid session key expiration")]
    InvalidSessionKeyExpiration,

    /// Signature Scheme Related Errors
    #[error("Invalid signature scheme")]
    InvalidSignatureScheme,

    /// Signer Execution Scheme Related Errors
    #[error("Invalid signer execution scheme")]
    InvalidSignerExecutionScheme,
    #[error("Signer execution account is not a signer")]
    SignerExecutionAccountNotASigner,

    /// P256 WebAuthn Related Errors
    #[error("Relying party ID too long. Max length is 32 bytes")]
    P256RelyingPartTooLong,
    #[error("Relying party does not get to include quotes")]
    P256RelyingPartIncludeQuotes,
    #[error("Relying party mismatch")]
    P256RelyingPartyMismatch,
    #[error("Client data hash mismatch")]
    P256ClientDataHashMismatch,
    #[error("Account is not writable")]
    P256AccountNotWritable,
    #[error("Invalid passkey Algorithm")]
    P256InvalidAlgorithm,
    #[error("Invalid public key encoding")]
    P256InvalidPublicKeyEncoding,
    #[error("Public key mismatch")]
    P256PublicKeyMismatch,
    #[error("User not verified")]
    P256UserNotVerified,
    #[error("User not present")]
    P256UserNotPresent,
}

impl From<ExternalSignatureProgramError> for ProgramError {
    #[track_caller]
    fn from(e: ExternalSignatureProgramError) -> Self {
        let variant = format!("{:?}", e);
        let message = e.to_string();
        let location = std::panic::Location::caller().to_string();

        let full_message = format!("{} - {} @ {}", variant, message, location);
        log!("{}", full_message.as_str());

        ProgramError::Custom(e as u32)
    }
}
