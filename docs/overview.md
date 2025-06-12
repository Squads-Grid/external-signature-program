# External Signature Program

A Solana program that enables secure instruction execution using external signatures and WebAuthn/Passkeys authentication.

## Program ID

```
ExtSgUPtP3JyKUysFw2S5fpL5fWfUPzGUQLd2bTwftXN
```

## Core Features

### Authentication

- **WebAuthn/Passkeys Support**
  - P-256 WebAuthn signature verification
  - Passwordless authentication via biometric or device-based methods
  - FIDO2/WebAuthn standard compliance

### Account Management

- **Externally Signed Accounts**
  - Secure account initialization and verification
  - Session key management with automatic rotation

### Instruction Processing

The program implements a consistent instruction processing system:

1. **Context Management**

   - Validates account ownership and permissions
   - Parses and verifies instruction arguments
   - Ensures signature scheme compatibility
   - Exposes validated and sanitized context throughout execution

2. **Execution Flow**
   - Verifies external signatures
   - Manages session keys
   - Executes instructions with proper permissions
   - Handles state updates

### Supported Instructions

| Discriminator | Instruction          | Description                                                |
| ------------- | -------------------- | ---------------------------------------------------------- |
| 0             | Initialize Account   | Creates and configures a new externally signed account     |
| 1             | Execute Instructions | Executes instructions with external signature verification |
| 2             | Refresh Session Key  | Updates the session key for enhanced security              |
| 3             | Execute with Session | Executes instructions using an active session key          |

### Technical Architecture

#### Account Data Trait

The program uses a trait-based system (`ExternallySignedAccountData`) to manage account data:

- **Type Safety**: Custom data types for initialization and verification
- **Flexibility**: Support for different signature schemes and account structures
- **Security**: Built-in validation and verification mechanisms

## Usage

### Core Purpose

The program enables Solana accounts to be controlled by external signature schemes at runtime. This allows for:

- Integration with external authentication systems
- Support for modern authentication methods (like WebAuthn/Passkeys)

### Extensibility

The program is designed to be extensible through its generic architecture:

- New signature schemes can be added by implementing the `ExternallySignedAccountData` trait
- Each scheme can define its own verification and initialization logic
- The core instruction processing remains unchanged when adding new schemes

### Integration

To integrate a new signature scheme:

1. Implement the `ExternallySignedAccountData` trait
2. Define scheme-specific verification logic
3. Add the scheme to the program's signature scheme enum
4. The program will automatically handle the new scheme's verification and execution

## Development

The program is written in Rust and uses the Solana program framework. It follows Solana's best practices for program development and security.
