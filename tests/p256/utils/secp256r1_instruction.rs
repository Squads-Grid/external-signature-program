use bytemuck::bytes_of;
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use solana_program::instruction::Instruction;
use solana_secp256r1_program::{
    Secp256r1SignatureOffsets, COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START, SECP256R1_ORDER,
    SIGNATURE_SERIALIZED_SIZE,
};

pub const FIELD_SIZE: usize = 32;
pub const SECP256R1_HALF_ORDER: [u8; FIELD_SIZE] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

pub fn new_secp256r1_instruction(
    signature: &[u8],
    message: &[u8],
    pubkey: &[u8],
    pubkey_offset: Option<(u8, u16)>,
) -> Result<Instruction, Box<dyn std::error::Error>> {
    let ecdsa_sig = EcdsaSig::from_der(&signature)?;
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();
    let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    // Incase of an r or s value of 31 bytes we need to pad it to 32 bytes
    let mut padded_r = vec![0u8; FIELD_SIZE];
    let mut padded_s = vec![0u8; FIELD_SIZE];
    padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
    padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

    signature[..FIELD_SIZE].copy_from_slice(&padded_r);
    signature[FIELD_SIZE..].copy_from_slice(&padded_s);

    // Check if s > half_order, if so, compute s = order - s
    let s_bignum = BigNum::from_slice(&s)?;
    let half_order = BigNum::from_slice(&SECP256R1_HALF_ORDER)?;
    let order = BigNum::from_slice(&SECP256R1_ORDER)?;
    if s_bignum > half_order {
        let mut new_s = BigNum::new()?;
        new_s.checked_sub(&order, &s_bignum)?;
        let new_s_bytes = new_s.to_vec();

        // Incase the new s value is 31 bytes we need to pad it to 32 bytes
        let mut new_padded_s = vec![0u8; FIELD_SIZE];
        new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);

        signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    }

    assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let (pubkey_instruction_index, pubkey_offset) = match pubkey_offset {
        Some((ix, offset)) => (ix as u16, offset as usize),
        None => (u16::MAX, DATA_START),
    };
    let signature_offset = match pubkey_instruction_index {
        u16::MAX => pubkey_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE),
        _ => DATA_START,
    };
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    let offsets = Secp256r1SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: pubkey_offset as u16,
        public_key_instruction_index: pubkey_instruction_index,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));
    if pubkey_instruction_index == u16::MAX {
        instruction_data.extend_from_slice(&pubkey);
    }
    instruction_data.extend_from_slice(&signature);
    instruction_data.extend_from_slice(message);

    Ok(Instruction {
        program_id: solana_secp256r1_program::id(),
        accounts: vec![],
        data: instruction_data,
    })
}
