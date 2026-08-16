# Copilot Instructions for TSS.MSR

## Project Overview

TSS.MSR is a multi-language TPM 2.0 Software Stack providing complete TPM 2.0 API abstractions. It contains parallel implementations in C# (.NET), C++, Java, TypeScript/Node.js, Python, and Rust, plus the **TssCodeGen** tool that auto-generates TPM type/command definitions across all languages from the TPM 2.0 specification documents.

## Architecture

### Code Generation Pipeline (TssCodeGen)

TssCodeGen is the central tool that keeps all language implementations in sync with the TPM 2.0 spec. It runs a 3-phase workflow:

1. **Table Extraction** — Parses TPM 2.0 spec Word documents into `RawTables.xml` (slow, uses Office interop; cached)
2. **Type Extraction** — Builds an AST of all TPM 2.0 entities from the raw tables
3. **Code Generation** — Language-specific generators (`CGenDotNet`, `CGenCpp`, `CGenJava`, `CGenNode`, `CGenPy`, `CGenRust`) emit target code

**Generated output files:**
- **TSS.NET:** `TSS.Net/X_TpmDefs.cs`
- **TSS.CPP:** `TpmTypes.h`, `Tpm2.h`, `TpmTypes.cpp` (between `<<AUTOGEN_BEGIN>>` / `<<AUTOGEN_END>>` markers)
- **TSS.Java:** One `.java` file per type in `src/tss/tpm/` plus `Tpm.java`
- **TSS.JS:** `src/TpmTypes.ts`, `src/Tpm.ts`
- **TSS.Py:** `src/TpmTypes.py`, `src/Tpm.py`

**⚠️ Never manually edit auto-generated files.** They will be overwritten by TssCodeGen. Look for file headers stating "automatically generated" or `<<AUTOGEN_BEGIN>>` markers.

### Extension Mechanism (.snips files)

Each language has `.snips` files (e.g., `TpmExtensions.js.snips`) that inject hand-written methods into auto-generated classes during code generation. Lines starting with `>> CLASSNAME` mark insertion points for the target class.

### Shared Patterns Across All Languages

- **TpmStructure base class** — All TPM types inherit from it; provides `toTpm()`/`initFromTpm()` (or language equivalent) for binary serialization
- **Union-as-interface** — TPM unions are represented as interfaces (e.g., `TPMU_SCHEME_KEYEDHASH`), with concrete structs implementing them. Each implementer provides `GetUnionSelector()` returning the discriminator value
- **Device abstraction** — Platform-specific TPM access (Linux `/dev/tpmrm0`, Windows TBS, TCP simulator) behind a common `TpmDevice` interface/abstract class

### Naming Conventions

| Aspect | TSS.NET | Other Languages |
|--------|---------|-----------------|
| Types | CamelCase, drops `TPM_`/`TPMS_` prefixes (`TpmAlgId`, `TpmRsa`) | Preserves spec names (`TPM_ALG_ID`, `TPMS_RSA_PARMS`) |
| Fields | PascalCase (`AuthPolicy`) | camelCase (JS/Py) or spec-style (Java/Rust) |
| Commands | `Tpm2.Hash()` | `tpm.Hash()` or similar |

## Build Commands

### C++ (`TSS.CPP/`)
```bash
make                    # Build library + samples (debug)
make CONFIG=release     # Release build
make test               # Build and run samples as tests
make clean
```

### Java (`TSS.Java/`)
```bash
mvn clean compile       # Compile
mvn clean install       # Build and install
```

### .NET (`TSS.NET/`)
```bash
dotnet build TSS.NET.sln
```
Targets: .NET 4.7.2 and .NET 5. Release builds use strong-name signing.

### Rust (`TSS.Rust/`)
```bash
cargo build
cargo test
cargo run --example tpm_samples
```

### TssCodeGen
```bash
TssCodeGen [-spec <path>] [-dest <path>] [-extract] [-dotNet] [-cpp] [-java] [-node] [-py]
```
Use `-extract` to force re-parsing of spec documents. Without it, uses cached `RawTables.xml`. Language flags generate only selected targets.

### Tpm2Tester
```bash
# Run specific test profiles against a TPM simulator
TestSuiteApp -device tcp -address localhost:2321 -randSeed startup nv

# Run a single test
TestSuiteApp -device tcp -tests TestCaseName

# Stress test
TestSuiteApp -device tcp -stress -threads 4 -mins 10
```

## Key Dependencies

| Language | Crypto Library | Native Access |
|----------|---------------|---------------|
| .NET | BouncyCastle.NetCore | - |
| Java | BouncyCastle (bcprov-jdk15on) | JNA |
| JS | - | ffi-napi, ref-napi |
| Rust | rsa, aes, sha1/sha2, hmac | windows crate (Win32) / libc (Unix) |
