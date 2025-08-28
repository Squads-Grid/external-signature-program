# External Signature Program

A Solana program that enables account creation and transaction execution using external signature schemes like WebAuthn/FIDO2, allowing users to interact with Solana using hardware keys, biometrics, or other external authenticators.

## Core Features

- **Account Initialization**: Create Solana accounts controlled by external signature schemes
- **Transaction Execution**: Execute Solana instructions using external signatures for authorization
- **Session Keys**: Temporary keys for reduced friction in recurring operations
- **Nonce-based Security**: Replay attack protection using slot hashes and nonces

## Supported Signature Schemes

- **P256 WebAuthn**: ECDSA signatures using the secp256r1 curve with WebAuthn attestation data

## Building and Testing

This project uses LiteSVM for testing Solana programs. To build and test the program:

```bash
# Build the program
cargo build-sbf

# Run tests
cargo test-sbf
```

## Instructions

1. **Initialize External Account**: Create a new account controlled by an external signature scheme
2. **Execute Instructions**: Execute Solana instructions using external signature verification
3. **Execute Instructions (Sessioned)**: Execute instructions using temporary session keys
4. **Refresh Session Key**: Update session key for continued low-friction operations

## Project Structure

- `src/` - Source code for the program
- `tests/` - Test files with P256/WebAuthn examples
- `docs/` - Documentation



## Roadmap

### SDKs
- **Rust SDK**: Native Rust client library for program interaction
- **TypeScript SDK**: JavaScript/TypeScript SDK for web and Node.js applications

### Additional Signature Schemes
- **secp256k1**: Bitcoin-style ECDSA signatures
- **ed25519**: EdDSA signatures (Solana native)
- **secp256r1 Native**: Direct P256 support without WebAuthn overhead

## Program ID

The program ID is: `ExtSgUPtP3JyKUysFw2S5fpL5fWfUPzGUQLd2bTwftXN`
