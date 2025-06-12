# P256 WebAuthn Implementation

## Overview

The program implements WebAuthn authentication using P-256 (secp256r1) signatures, providing a secure way to authenticate users through passkeys. This implementation follows the WebAuthn standard while integrating with Solana's security model.

## Integration with Solana

### Precompile Usage

- Leverages Solana's P-256 precompile for signature verification
- Efficient on-chain signature validation
- Native integration with Solana's security model

### Account Derivation

```rust
fn derive_account(args: Self::DeriveAccountArgs) -> Result<Self::AccountSeeds, ProgramError> {
    let public_key_hash = hash(&args.public_key);
    let (derived_key, bump) = try_find_program_address(
        &[b"passkey", &public_key_hash],
        &crate::ID
    ).unwrap();
    // ...
}
```

- Deterministic account derivation
- Uses public key hash for uniqueness
- PDA-based account structure

## Core Components

### Account Structure

```rust
pub struct P256WebauthnAccountData {
    _header: AccountHeader,
    rp_id_info: RpIdInformation,
    public_key: CompressedP256PublicKey,
    padding: [u8; 2],
    session_key: SessionKey,
    counter: u64,
}
```

- **RpIdInformation**: Stores the relying party (RP) ID and its hash
- **CompressedP256PublicKey**: P-256 public key in compressed format
- **SessionKey**: Optional session key for efficient repeated operations
- **Counter**: WebAuthn signature counter for replay protection

### Data Types

#### Initialization Data

```rust
pub struct P256RawInitializationData {
    pub rp_id: SmallVec<u8, u8>,
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}
```

#### Verification Data

```rust
pub struct P256RawVerificationData {
    pub public_key: [u8; 33],
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}
```

## Authentication Flow

### 1. Account Initialization

- Client provides:
  - Relying Party ID
  - P-256 public key
  - Client data JSON parameters
- Program:
  - Derives account address using public key hash
  - Stores RP ID and public key
  - Initializes counter

### 2. Signature Verification

The verification process follows WebAuthn standards:

1. **Precompile Parsing**

   - Extracts P-256 signature, message and pubkey from Solana precompile
   - Validates signature count and format

2. **Authentication Data Processing**

   - Parses WebAuthn authentication data
   - Verifies RP ID hash matches stored value
   - Validates signature counter

3. **Client Data Verification**
   - Reconstructs client data JSON
   - Verifies hash matches authentication data
   - Ensures proper nonce and challenge handling

### 3. Session Management

- Optional session keys for more efficient execution
- Keys expire after configurable duration
- Prevents unnecessary WebAuthn operations and overhead

## Security Features

### Relying Party Verification

- RP ID hash verification prevents phishing attacks
- Ensures signatures are bound to correct domain

### Counter Protection

- Signature counter prevents replay attacks
- Counter must always increase
- Prevents reuse of old signatures

### Public Key Management

- P-256 public keys stored in compressed format
- Efficient storage and verification
- Standard WebAuthn key format

## Instruction Execution

### Client Data JSON Reconstruction

The program reconstructs the client data JSON on-chain using minimal stored parameters (flags and bytes) rather than storing the full JSON. Since WebAuthn signatures are over the hash of the client data JSON, the program must reconstruct and hash the JSON to verify the signature matches.

### Instruction Payload Generation

For instruction execution, the payload (challenge) is constructed by concatenating:

1. The nonce signer's public key
2. A recent slot hash (for expiration)
3. The actual instruction payload

This ensures:

- The payload is bound to a specific nonce signer
- The payload expires with the slot hash
- The payload cannot be replayed without the nonce signer's cooperation

### Instruction Execution Payload

The instruction payload is constructed by serializing:

1. Slot hash
2. Nonce signer's public key
3. Account information:
   - Account public keys
   - Signer flags
   - Writable flags
4. Instruction data:
   - Number of instructions
   - Program IDs
   - Account indices
   - Instruction data

This serialized payload is then hashed to create the final challenge that is signed.
