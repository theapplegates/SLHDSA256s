# SLHDSA256s + MLKEM1024_X448 Post-Quantum Key Generation

This guide documents how to generate OpenPGP V6 certificates using post-quantum cryptography algorithms with Sequoia PGP.

## Overview

Successfully implements V6 OpenPGP certificates with:
- **Primary key**: SLHDSA256s (certification + signing)
- **Signing subkey**: SLHDSA256s
- **Encryption subkey**: MLKEM1024_X448
- **Profile**: V6 (RFC 9580)
- **Hash algorithm**: SHA3-512 (automatic with V6)

## Branch Information

- **Branch**: `malte/certbuilder_pk_algos`
- **Repository**: https://gitlab.com/sequoia-pgp/sequoia
- **Key commit**: `ddc3006a` - Add set_encryption_algorithm and set_signing_algorithm to CertBuilder
- **Author**: Malte Meiboom
- **Date**: November 26, 2025

### Fetching the Branch

```bash
# Add upstream remote (if not already added)
git remote add upstream https://gitlab.com/sequoia-pgp/sequoia.git

# Fetch the PQC branch
git fetch upstream malte/certbuilder_pk_algos

# Checkout the branch
git checkout -b malte/certbuilder_pk_algos upstream/malte/certbuilder_pk_algos
```

## Requirements

### System Requirements
- **Rust**: 1.85 or higher
- **OpenSSL**: Version 3.x (OpenSSL 4.0 beta or higher recommended for full PQC support)
  - On macOS with Homebrew: `brew install openssl@3`
  - On Debian/Ubuntu: `apt install libssl-dev`
  - On Fedora: `dnf install openssl-devel`

### Environment Variables (macOS with Homebrew)

If you're on macOS with Homebrew OpenSSL, set these environment variables:

```bash
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

**Note**: On Linux, the system OpenSSL is typically used and these variables are usually not needed.

## Files Created

1. **openpgp/examples/slhdsa_mlkem_demo.rs** - Example demonstrating PQC key generation
2. **automation_scripts.sh** - Automation script for easy key generation
3. **PQC_KEY_GENERATION.md** - This documentation file

## Usage

### Quick Start with Automation Script

The automation script handles environment setup and build configuration automatically:

```bash
# Check system requirements
./automation_scripts.sh check

# Build the example
./automation_scripts.sh build

# Generate keys with default values
./automation_scripts.sh generate

# Generate keys with custom name and email
./automation_scripts.sh generate "Your Name" "you@example.com"

# Show key information
./automation_scripts.sh info

# Run tests
./automation_scripts.sh test

# Clean up generated keys
./automation_scripts.sh clean

# Show help
./automation_scripts.sh help
```

### Manual Build and Usage

1. **Build with OpenSSL backend**:
   ```bash
   cargo build --release -p sequoia-openpgp \
     --example slhdsa_mlkem_demo \
     --no-default-features \
     --features crypto-openssl,compression
   ```

2. **Run the example**:
   ```bash
   cargo run --release -p sequoia-openpgp \
     --example slhdsa_mlkem_demo \
     --no-default-features \
     --features crypto-openssl,compression \
     -- "Your Name" "you@example.com"
   ```

3. **Run tests**:
   ```bash
   cargo test -p sequoia-openpgp \
     --no-default-features \
     --features crypto-openssl,compression
   ```

### Code Example

```rust
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::{KeyFlags, PublicKeyAlgorithm};
use openpgp::Profile;

// Generate a V6 certificate with PQC algorithms
let (cert, _revocation) = CertBuilder::new()
    .add_userid("user@example.com")
    .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
    .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
    // Set SLHDSA256s for all signing operations
    .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)?
    // Set MLKEM1024_X448 for all encryption operations
    .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)?
    .add_signing_subkey()
    .add_storage_encryption_subkey()
    .generate()?;
```

## Key Features

### New CertBuilder Methods

The `malte/certbuilder_pk_algos` branch adds two new methods to `CertBuilder`:

1. **`set_signing_algorithm(algo, curve, bits)`**
   - Sets the algorithm for all signing operations (primary key and signing subkeys)
   - Parameters:
     - `algo`: Public key algorithm (e.g., `PublicKeyAlgorithm::SLHDSA256s`)
     - `curve`: Optional curve parameter (use `None` for PQC algorithms)
     - `bits`: Optional key size in bits (use `None` for PQC algorithms)

2. **`set_encryption_algorithm(algo, curve, bits)`**
   - Sets the algorithm for all encryption operations (encryption subkeys)
   - Parameters: Same as `set_signing_algorithm()`

These methods allow independent control of signing and encryption algorithms, enabling mixing of different PQC algorithms without needing `CipherSuite::Custom`.

**Important**: The order matters. These functions overwrite existing settings, so the last call wins.

### Crypto Backend Support

| Backend | SLHDSA256s | MLKEM1024_X448 | Status |
|---------|------------|----------------|--------|
| Nettle  | ❌ No      | ❌ No          | Not supported |
| **OpenSSL** | ✅ Yes | ✅ Yes        | **Recommended** |
| Botan   | ❓ Unknown | ❓ Unknown     | Not tested |
| CNG     | ❓ Unknown | ❓ Unknown     | Not tested |
| Rust    | ❌ No      | ❌ No          | Not supported |

**Note**: Only the OpenSSL backend currently supports the required PQC algorithms. You **must** build with `--no-default-features --features crypto-openssl,compression`.

## Generated Key Characteristics

- **Public key size**: ~200 KB
- **Secret key size**: ~200 KB
- **Fingerprint format**: V6 (256-bit SHA256)
- **Large size**: Expected due to PQC algorithm overhead

### Example Output

```
=== Post-Quantum Certificate Generation ===
User ID: Paul Applegate <me@paulapplegate.com>
Profile: V6 (RFC 9580)
Primary key: SLHDSA256s (certification + signing)
Signing subkey: SLHDSA256s
Encryption subkey: MLKEM1024_X448

✓ Crypto backend supports SLHDSA256s
✓ Crypto backend supports MLKEM1024_X448

Generating certificate...
✓ Certificate generated successfully

=== Certificate Information ===
Fingerprint: 7BE9FD696DD2342233D2103CF56D211532473D513C6CF07A2A8BCA61E2DE3304
Version: 6

Primary key:
  Algorithm: SLHDSA256s
  Key flags: KeyFlags(CS)

Subkeys:
  Subkey 1:
    Algorithm: SLHDSA256s
    Key flags: KeyFlags(S)

  Subkey 2:
    Algorithm: MLKEM1024_X448
    Key flags: KeyFlags(Er)

=== Verification ===
✓ Primary key: SLHDSA256s
✓ Signing subkey: SLHDSA256s
✓ Encryption subkey: MLKEM1024_X448

=== Exporting Keys ===
✓ Public key exported: Paul_Applegate_public.asc (204935 bytes)
✓ Secret key exported: Paul_Applegate_secret.asc (205453 bytes)

=== Summary ===
Successfully generated V6 certificate with post-quantum cryptography:
  • Primary: SLHDSA256s (certification + signing)
  • Subkey 1: SLHDSA256s (signing)
  • Subkey 2: MLKEM1024_X448 (encryption)

Note: Large key sizes (~200KB) are expected for post-quantum algorithms.
```

## Algorithm Details

### SLHDSA256s (Signing)
- **Type**: Stateless Hash-Based Signature Scheme
- **Security level**: NIST Level 5 (highest)
- **Internal hash**: SHAKE-256 (FIPS 205)
- **Usage**: Certification and signing operations
- **Post-quantum**: Yes (stateless hash-based signatures)
- **Standardization**: FIPS 205

SLHDSA (Stateless Hash-Based Digital Signature Algorithm) is based on the SPHINCS+ signature scheme. It provides post-quantum security through hash-based cryptography rather than relying on number-theoretic hardness assumptions.

### MLKEM1024_X448 (Encryption)
- **Type**: Module-Lattice-Based Key Encapsulation Mechanism + X448 ECDH
- **Security level**: NIST Level 5 (highest)
- **Usage**: Storage and transport encryption
- **Post-quantum**: Yes (hybrid with classical X448)
- **Standardization**: FIPS 203 (ML-KEM)

ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism), formerly known as CRYSTALS-Kyber, is a lattice-based cryptographic algorithm. The hybrid construction combines ML-KEM1024 with classical X448 elliptic curve for defense-in-depth.

### SHA3-512 (Hashing)
- **Automatically used with V6 keys**
- **Complements SLHDSA's internal SHAKE-256**
- **NIST approved hash function**
- **Post-quantum resistant**

## Troubleshooting

### "library 'crypto' not found" Error

**Problem**: OpenSSL library not found by linker.

**Solution**:
1. Ensure OpenSSL 3.x is installed
2. Set the environment variables listed above (macOS)
3. On Linux, install development packages: `libssl-dev` (Debian) or `openssl-devel` (Fedora)

### "Unsupported public key algorithm: SLHDSA256s" Error

**Problem**: Wrong crypto backend being used (likely Nettle, which is the default).

**Solution**: Build with the OpenSSL backend:
```bash
cargo build --no-default-features --features crypto-openssl,compression
```

**Always use** `--no-default-features` to disable Nettle, then explicitly enable OpenSSL.

### "Unsupported public key algorithm: MLKEM1024_X448" Error

**Problem**: Same as above - wrong crypto backend.

**Solution**: Same as above - use OpenSSL backend.

### OpenSSL Version Issues

**Problem**: PQC algorithms may not be fully supported in older OpenSSL versions.

**Solution**:
- OpenSSL 3.x has basic PQC support
- OpenSSL 4.0 beta or higher recommended for full PQC support
- Check version: `openssl version`
- Update if needed using your package manager

### Build Fails with "feature resolution error"

**Problem**: Conflicting crypto backend features enabled.

**Solution**:
- Ensure you use `--no-default-features`
- Only enable ONE crypto backend at a time
- Correct: `--no-default-features --features crypto-openssl,compression`
- Wrong: `--features crypto-openssl` (leaves default Nettle enabled)

## Testing

### Run All Tests
```bash
cargo test -p sequoia-openpgp \
  --no-default-features \
  --features crypto-openssl,compression
```

### Run Specific Tests
```bash
# Test certificate building
cargo test -p sequoia-openpgp \
  --no-default-features \
  --features crypto-openssl,compression \
  cert::builder

# Test PQC-specific functionality
cargo test -p sequoia-openpgp \
  --no-default-features \
  --features crypto-openssl,compression \
  pqc
```

## References

- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) - OpenPGP Version 6
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLHDSA Specification
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Specification
- [draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) - PQC in OpenPGP (Draft)
- [Sequoia PGP](https://sequoia-pgp.org/) - Official website
- [Sequoia GitLab](https://gitlab.com/sequoia-pgp/sequoia) - Source repository

## Security Considerations

### Post-Quantum Security

These algorithms are designed to resist attacks from quantum computers:

- **SLHDSA256s**: Provides post-quantum security through hash-based signatures. Security does not depend on the hardness of number-theoretic problems.
- **MLKEM1024_X448**: Provides post-quantum security through lattice-based cryptography, while the X448 component provides classical security as a fallback.

### Key Management

- **Key Size**: Post-quantum keys are significantly larger than classical keys. This is expected and normal.
- **Performance**: PQC operations may be slower than classical algorithms. This is a trade-off for quantum resistance.
- **Backup**: Ensure proper backup of secret keys. Recovery is not possible without the secret key file.

### Migration Path

1. **Generate new PQC keys** using this guide
2. **Keep existing classical keys** for backwards compatibility
3. **Gradually transition** to PQC keys as needed
4. **Test thoroughly** before production use

## Contributing

When working with this codebase:
- Always use the `crypto-openssl` backend for PQC algorithms
- Test with `cargo test -p sequoia-openpgp --no-default-features --features crypto-openssl,compression`
- Follow the patterns established in the example code
- Update this documentation for any changes

## License

Sequoia PGP is licensed under the LGPL-2.0-or-later license.

## Support

For questions, issues, or contributions:
- **Mailing list**: devel-subscribe@lists.sequoia-pgp.org
- **IRC**: #sequoia on OFTC
- **GitLab**: https://gitlab.com/sequoia-pgp/sequoia/issues

---

**Last Updated**: January 2026
**Branch**: malte/certbuilder_pk_algos
**Commit**: ddc3006a
