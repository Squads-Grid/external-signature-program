use std::marker::PhantomData;

use bytemuck::{Pod, Zeroable};
use pinocchio::{
    account_info::Ref,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::instructions::{Instructions, IntrospectedInstruction},
};
use pinocchio_pubkey::pubkey;

use crate::errors::ExternalSignatureProgramError;
/// Since all precompiles have to abide by the same interface, this struct and
/// its methods are helpers to more easily access precompile data

/// Note: The exception here is the legacy secp256k1 precompile, which uses a
/// different offset format.

#[derive(Default, Debug, Copy, Zeroable, Pod, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct SignatureOffsets {
    /// Offset to compact secp256r1 signature of 64 bytes
    pub signature_offset: u16,

    /// Instruction index where the signature can be found
    pub signature_instruction_index: u16,

    /// Offset to public key
    pub public_key_offset: u16,

    /// Instruction index where the public key can be found
    pub public_key_instruction_index: u16,

    /// Offset to the start of message data
    pub message_data_offset: u16,

    /// Size of message data in bytes
    pub message_data_size: u16,

    /// Instruction index where the message data can be found
    pub message_instruction_index: u16,
}

pub const LEGACY_SECP256K1_PRECOMPILE_ID: Pubkey =
    pubkey!("KeccakSecp256k11111111111111111111111111111");
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, serde::Deserialize)]
#[repr(C)]
pub struct LegacySecp256k1SignatureOffsets {
    /// Offset to compact secp256r1 signature of 64 bytes
    pub signature_offset: u16,

    /// Instruction index where the signature can be found
    pub signature_instruction_index: u8,

    /// Offset to public key
    pub public_key_offset: u16,

    /// Instruction index where the public key can be found
    pub public_key_instruction_index: u8,

    /// Offset to the start of message data
    pub message_data_offset: u16,

    /// Size of message data in bytes
    pub message_data_size: u16,

    /// Instruction index where the message data can be found
    pub message_instruction_index: u8,
}

impl Into<SignatureOffsets> for LegacySecp256k1SignatureOffsets {
    fn into(self) -> SignatureOffsets {
        SignatureOffsets {
            signature_offset: self.signature_offset,
            signature_instruction_index: self.signature_instruction_index as u16,
            public_key_offset: self.public_key_offset,
            public_key_instruction_index: self.public_key_instruction_index as u16,
            message_data_offset: self.message_data_offset,
            message_data_size: self.message_data_size,
            message_instruction_index: self.message_instruction_index as u16,
        }
    }
}

/// Struct for easy access to a signature payload
pub struct SignaturePayload<'a> {
    pub signature: &'a [u8],
    pub public_key: &'a [u8],
    pub message: &'a [u8],
    _marker: PhantomData<&'a Instructions<Ref<'a, [u8]>>>,
}

pub struct PrecompileParser<'a, T: PrecompileInfo> {
    pub precompile_ix_data: &'a [u8],
    pub instructions_sysvar: &'a Instructions<Ref<'a, [u8]>>,
    _marker: std::marker::PhantomData<T>,
}

pub fn get_data_slice<'a>(data: &'a [u8], offset: usize, size: usize) -> &'a [u8] {
    &data[offset as usize..offset as usize + size as usize]
}

pub fn get_data_slice_raw<'a, 'b>(data: &'a [u8], offset: usize, size: usize) -> &'b [u8]
where
    'b: 'a,
{
    unsafe {
        let ptr = data.as_ptr().add(offset);
        let slice = core::slice::from_raw_parts(ptr, size);
        slice
    }
}

impl<'a, 'b, T: PrecompileInfo> PrecompileParser<'a, T> {
    pub fn new(
        precompile_ix: &'a IntrospectedInstruction<'a>,
        instructions_sysvar: &'a Instructions<Ref<'a, [u8]>>,
    ) -> Result<Self, ProgramError> {
        // Check that the precompile id matches
        if precompile_ix.get_program_id() != &T::get_precompile_id() {
            return Err(ProgramError::Custom(
                ExternalSignatureProgramError::InvalidPrecompileId as u32,
            ));
        }
        Ok(Self {
            precompile_ix_data: precompile_ix.get_instruction_data(),
            instructions_sysvar: instructions_sysvar,
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns the number of signatures
    pub fn num_signatures(&self) -> usize {
        self.precompile_ix_data[0] as usize
    }

    /// Returns the n'th signature payload within the precompile instruction
    pub fn get_signature_payload(&self, index: usize) -> Result<SignaturePayload, ProgramError> {
        // Check that the index is within bounds
        if index >= self.num_signatures() {
            return Err(ProgramError::Custom(
                ExternalSignatureProgramError::InvalidSignatureIndex as u32,
            ));
        }

        // Get the data start offset and signature offsets size
        let data_start_offset = T::get_data_start_offset();
        let signature_offsets_size = T::get_signature_offsets_size();

        // Get the offset start and payload
        let offset_start = data_start_offset + signature_offsets_size * index;
        let payload: SignaturePayload = match T::get_precompile_id() {
            // TODO: Implement legacy secp256k1 precompile since it uses
            // different offsets from the other precompiles
            LEGACY_SECP256K1_PRECOMPILE_ID => {
                panic!("Not implemented");
            }
            SECP256R1_PRECOMPILE_ID => {
                // Get the signature offsets for the desired index
                let offset = bytemuck::try_from_bytes::<SignatureOffsets>(
                    &self.precompile_ix_data[offset_start..offset_start + signature_offsets_size],
                )
                .map_err(|_| ExternalSignatureProgramError::InvalidSignatureOffset)?;

                // Get the signature
                let signature = match offset.signature_instruction_index {
                    u16::MAX => get_data_slice(
                        self.precompile_ix_data,
                        offset.signature_offset as usize,
                        T::get_signature_size(),
                    ),
                    _ => {
                        let instruction = self
                            .instructions_sysvar
                            .load_instruction_at(offset.signature_instruction_index as usize)
                            .map_err(|_| ExternalSignatureProgramError::InvalidSignatureOffset)?;
                        let ix_data = instruction.get_instruction_data();
                        get_data_slice_raw(
                            ix_data,
                            offset.signature_offset as usize,
                            T::get_signature_size(),
                        )
                    }
                };
                // Get the public key
                let public_key = match offset.public_key_instruction_index {
                    u16::MAX => get_data_slice(
                        self.precompile_ix_data,
                        offset.public_key_offset as usize,
                        T::get_public_key_size(),
                    ),
                    _ => {
                        let instruction = self
                            .instructions_sysvar
                            .load_instruction_at(offset.public_key_instruction_index as usize)
                            .map_err(|_| ExternalSignatureProgramError::InvalidSignatureOffset)?;
                        let ix_data = instruction.get_instruction_data();
                        get_data_slice_raw(
                            ix_data,
                            offset.public_key_offset as usize,
                            T::get_public_key_size(),
                        )
                    }
                };

                // Get the message
                let message = match offset.message_instruction_index {
                    u16::MAX => get_data_slice(
                        self.precompile_ix_data,
                        offset.message_data_offset as usize,
                        offset.message_data_size as usize,
                    ),
                    _ => {
                        let instruction = self
                            .instructions_sysvar
                            .load_instruction_at(offset.message_instruction_index as usize)
                            .map_err(|_| ExternalSignatureProgramError::InvalidSignatureOffset)?;
                        let ix_data = instruction.get_instruction_data();
                        get_data_slice_raw(
                            ix_data,
                            offset.message_data_offset as usize,
                            offset.message_data_size as usize,
                        )
                    }
                };
                SignaturePayload {
                    signature,
                    public_key,
                    message,
                    _marker: PhantomData,
                }
            }
            _ => {
                panic!("Precompile not implemented");
            }
        };
        Ok(payload)
    }
}

pub trait PrecompileInfo {
    const SIGNATURE_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_OFFSETS_SIZE: usize;
    const NUM_SIGNATURES_SIZE: usize;
    fn get_precompile_id() -> Pubkey;
    fn get_signature_size() -> usize;
    fn get_public_key_size() -> usize;
    fn get_signature_offsets_size() -> usize;
    fn get_data_start_offset() -> usize;
}
pub struct LegacySecp256k1Precompile;

pub struct Secp256r1Precompile;
pub const SECP256R1_PRECOMPILE_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");
pub const SECP256R1_SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SECP256R1_PUBLIC_KEY_SERIALIZED_SIZE: usize = 33;
pub const SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SECP256R1_NUM_SIGNATURES_SERIALIZED_SIZE: usize = 2;

impl PrecompileInfo for Secp256r1Precompile {
    const SIGNATURE_SIZE: usize = SECP256R1_SIGNATURE_SERIALIZED_SIZE;
    const PUBLIC_KEY_SIZE: usize = SECP256R1_PUBLIC_KEY_SERIALIZED_SIZE;
    const SIGNATURE_OFFSETS_SIZE: usize = SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    const NUM_SIGNATURES_SIZE: usize = SECP256R1_NUM_SIGNATURES_SERIALIZED_SIZE;
    fn get_precompile_id() -> Pubkey {
        SECP256R1_PRECOMPILE_ID
    }
    fn get_signature_size() -> usize {
        SECP256R1_SIGNATURE_SERIALIZED_SIZE
    }
    fn get_public_key_size() -> usize {
        SECP256R1_PUBLIC_KEY_SERIALIZED_SIZE
    }
    fn get_signature_offsets_size() -> usize {
        SECP256R1_SIGNATURE_OFFSETS_SERIALIZED_SIZE
    }
    fn get_data_start_offset() -> usize {
        SECP256R1_NUM_SIGNATURES_SERIALIZED_SIZE
    }
}
