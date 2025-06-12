# Nonce Mechanism for External Signatures

## Problem
Unlike Solana's native transaction signatures which are enforced at the runtime level and naturally expire after 150 blocks, externally signed payloads present unique challenges:

1. Payload Persistence
   - Signed payloads remain visible and accessible on the blockchain indefinitely
   - No automatic expiration mechanism exists for these payloads
   - Native transaction signatures expire with their blockhash after 150 blocks

2. Replay Vulnerability
   - Even with some stored state of `interaction_counter` on the program level,
     failed transactions could be replayed within an expiration window
   - Contrasts with native signatures which prevent replay through signature/blockhash binding

This creates a security gap where externally signed transactions lack the same temporal constraints and replay protections inherent to Solana's native transaction signing system.

## Overview

The program implements a nonce mechanism to provide security guarantees equivalent to Solana's native transaction signing system for externally signed payloads. This ensures:

- Expiration within 150 slots
- Unpredictability of future nonces
- Prevention of transaction replay attacks, even on transaction failure (via
  signer substitution or blockhash modification)

## Components

### Slot Hash as Base Nonce

- Uses Solana's slot hashes as the base nonce
- Slot hashes occur at the same or higher frequency than block hashes
- Each slot hash is a hash of the current bank state, making it unpredictable
- Provides natural expiration within 150 slots

### Nonce Signer

To prevent replay attacks, the system requires:

1. A additional nonce signature from a controlled/trusted signer on the solana transaction
2. The nonce signer's public key included in the signed payload

## Security Guarantees

### Expiration

- Payloads expire after 150 slots
- Natural expiration through slot hash system
- Prevents long-term storage of signed payloads

### Unpredictability

- Slot hashes are unpredictable
- Based on current bank state
- Prevents pre-computation of future nonces

### Replay Protection

The system prevents replay attacks through:

1. **Payload Verification**

   - Signed payload must include nonce signer's public key
   - Program verifies the reconstructed message matches the submitted payload

2. **Transaction Binding**
   - Nonce signer must sign the Solana transaction
   - Solana runtime prevents replay via fee payer or blockhash modification
     as the attached nonce signature will be saved for the duration of the
     slothash, on both successful or failed transactions

## Payload Construction

When signing a payload, the message is constructed as:

```
[nonce_signer_pubkey][recent_slothash][actual_payload]
```

This ensures:

- The payload is bound to a specific nonce signer
- The payload is bound to a specific slot
- The payload cannot be replayed without the nonce signer's cooperation
