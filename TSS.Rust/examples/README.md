# TSS.Rust Examples

This directory contains example code for using the TSS.Rust library.

## Running the Examples

To run the main samples using the Windows TBS device (hardware TPM):

```bash
cargo run --example tpm_samples
```

To connect to a TPM simulator instead:

```bash
cargo run --example tpm_samples -- sim
```

## Available Samples

`tpm_samples.rs` contains a comprehensive set of 37 samples demonstrating TPM 2.0 operations:

### Basic Operations
- **Random** - `GetRandom` / `StirRandom`
- **Hash** - Single-shot and sequence-based hashing (SHA-1, SHA-256)
- **HMAC** - HMAC key creation, sequence and direct computation
- **PCR** - Event, Read, Extend, Reset operations
- **Counter/Timer** - `ReadClock`, `ClockSet`, `ClockRateAdjust`
- **GetCapability** - Enumerate algorithms and commands

### Key Management
- **Primary Keys** - RSA primary creation, signing, `EvictControl` persistence
- **Child Keys** - Child signing keys, `ContextSave`/`Load`, `ObjectChangeAuth`
- **RSA Encrypt/Decrypt** - RSA-OAEP encryption and decryption
- **Encrypt/Decrypt** - Symmetric AES encryption
- **Software Keys** - Import external RSA keys, cross-validate signatures

### Auth Sessions
- **Auth Sessions** - HMAC session usage for key creation and signing
- **Seeded Session** - Salted HMAC sessions (RSA-OAEP salt encryption)
- **Bound Session** - Sessions bound to a specific entity
- **Session Encryption** - Parameter encryption/decryption (`decrypt`/`encrypt` attributes)

### NV Storage
- **NV** - Define/Write/Read/Undefine for simple, counter, bitfield, and extend NV indices

### Policy
- **Policy Simplest** - `PolicyCommandCode`
- **Policy PCR** - `PolicyPCR` gating access on PCR values
- **Policy OR** - `PolicyOR` branching
- **Policy With Passwords** - `PolicyPassword` / `PolicyAuthValue`
- **Policy CpHash** - Restricting to specific command parameters
- **Policy CounterTimer** - Time-limited access
- **Policy Secret** - Authorization from another entity
- **Policy NV** - NV-based policy conditions
- **Policy NameHash** - Restricting to specific handles
- **Policy Locality** - Locality-based restrictions (trial only on TBS)
- **Policy Tree** - `PolicyTree` abstraction with multiple scenarios

### Attestation & Audit
- **Attestation** - PCR quoting, time quoting, key certification with signature verification
- **Audit** - Command audit and session audit

### Other
- **Unseal** - Seal/unseal with PCR + password policy
- **Import/Duplicate** - Key duplication and import
- **ReWrap** - Key rewrapping between parents
- **Activate Credentials** - `MakeCredential` / `ActivateCredential`
- **Async** - Asynchronous command dispatch
- **Dictionary Attack** - DA lockout reset and parameter configuration
- **Misc Admin** - `SelfTest`, `ClockSet`, `ClearControl`
- **Allow Errors** - Error handling demonstration
