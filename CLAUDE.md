# CLAUDE.md - AI Assistant Guide for Sequoia-SQ

This document provides comprehensive guidance for AI assistants working with the Sequoia-SQ codebase.

## Project Overview

**Project:** Sequoia-SQ
**Description:** A command-line tool and high-level library for OpenPGP operations
**Language:** Rust (Edition 2021, MSRV 1.85)
**Repository:** https://gitlab.com/sequoia-pgp/sequoia-sq
**License:** LGPL-2.0-or-later
**Total Source Files:** 269 Rust files

### What is Sequoia-SQ?

Sequoia-SQ is part of the Sequoia-PGP project, an OpenPGP implementation in Rust. This repository contains:

1. **`sequoia` library** (`lib/`) - A high-level cryptographic library providing OpenPGP operations
2. **`sequoia-sq` tool** (`tool/`) - A command-line tool (`sq`) for end-users to perform OpenPGP operations

The project emphasizes security, usability, and modern cryptographic practices.

## Repository Structure

```
SLHDSA256s/
├── lib/                          # High-level library (sequoia)
│   ├── src/                      # Library source code
│   │   ├── lib.rs               # Main library entry point
│   │   ├── config/              # Configuration management (73KB)
│   │   ├── cert/                # Certificate operations
│   │   ├── key/                 # Key management
│   │   ├── pki/                 # PKI operations
│   │   ├── types/               # Type definitions (15+ modules)
│   │   ├── encrypt.rs           # Encryption (31KB)
│   │   ├── decrypt.rs           # Decryption (45KB)
│   │   ├── sign.rs              # Signing (40KB)
│   │   ├── verify.rs            # Verification (49KB)
│   │   ├── inspect.rs           # Certificate inspection (37KB)
│   │   ├── list.rs              # Listing (38KB)
│   │   └── ...                  # Additional modules
│   ├── Cargo.toml               # Library manifest
│   └── README.md                # Library documentation
│
├── tool/                         # CLI tool (sequoia-sq)
│   ├── src/
│   │   ├── main.rs              # CLI entry point (17KB)
│   │   ├── sq.rs                # Main CLI structure (51KB)
│   │   ├── cli/                 # CLI argument definitions
│   │   │   ├── cert.rs          # Certificate commands
│   │   │   ├── key.rs           # Key commands
│   │   │   ├── sign.rs          # Signing commands
│   │   │   ├── verify.rs        # Verification commands
│   │   │   ├── encrypt.rs       # Encryption commands
│   │   │   ├── decrypt.rs       # Decryption commands
│   │   │   ├── network/         # Network operations
│   │   │   ├── pki/             # PKI operations
│   │   │   ├── packet/          # Packet operations
│   │   │   ├── config/          # Configuration commands
│   │   │   └── types/           # CLI type definitions
│   │   ├── commands/            # Command implementations
│   │   ├── common/              # Shared utilities
│   │   └── output/              # Output formatting
│   ├── tests/
│   │   ├── integration/         # 44+ integration test modules
│   │   │   ├── common.rs        # Test utilities
│   │   │   └── sq_*.rs          # Individual test files
│   │   ├── data/                # Test data (keys, messages, etc.)
│   │   └── sq-subplot.rs        # Subplot test harness
│   ├── subplot/                 # Subplot test bindings
│   ├── build.rs                 # Build script (163 lines)
│   ├── Containerfile            # OCI image definition
│   ├── Cargo.toml               # Tool manifest
│   ├── sq.subplot               # Subplot definition
│   └── sq-subplot.md            # Subplot documentation (52KB)
│
├── Cargo.toml                    # Workspace manifest
├── Cargo.lock                    # Dependency lock file
├── .gitlab-ci.yml               # GitLab CI/CD configuration
├── openpgp-policy.toml          # OpenPGP policy definitions
└── README.md                     # Project overview
```

## Development Setup

### Prerequisites

1. **Rust Toolchain**
   - Minimum Supported Rust Version: 1.85
   - Install via rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

2. **Build Dependencies**
   - See [sequoia-openpgp's README](https://gitlab.com/sequoia-pgp/sequoia#requirements-and-msrv) for system dependencies
   - Typically includes: nettle, clang, pkg-config

3. **Optional Tools**
   - Podman/Docker (for container builds)
   - Pandoc (for documentation generation)

### Building from Source

```bash
# Clone the repository
git clone https://gitlab.com/sequoia-pgp/sequoia-sq.git
cd sequoia-sq

# Build the library and tool
cargo build

# Build with all features
cargo build --all-features

# Build release version
cargo build --release

# Build with custom asset output directory
ASSET_OUT_DIR=/tmp/assets cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run library tests only
cargo test -p sequoia

# Run tool tests only
cargo test -p sequoia-sq

# Run specific integration test
cargo test --test integration sq_encrypt

# Run subplot tests (requires subplot feature)
cargo test --features subplot
```

### Building with Container

```bash
cd tool
podman build -f Containerfile -t sq .
podman run --rm -i sq --help

# With persistent state
mkdir sq-container
podman run --rm -i -v $PWD/sq-container:/sequoia sq --help
```

## Key Dependencies

### Cryptographic Core
- **sequoia-openpgp** (v2) - Core OpenPGP implementation
- **sequoia-net** (v0.30) - Network operations (keyservers, WKD, DANE)
- **sequoia-autocrypt** (v0.26) - Autocrypt support
- **sequoia-cert-store** (v0.7) - Certificate storage
- **sequoia-keystore** (v0.7) - Key storage
- **sequoia-wot** (v0.15) - Web of Trust
- **sequoia-policy-config** (v0.8) - Policy configuration

### CLI Framework
- **clap** (v4.5) - Command-line argument parsing with derive macros
- **clap_complete** (v4) - Shell completion generation
- **termcolor** (v1.2) - Colored terminal output
- **textwrap** (v0.15+) - Text wrapping

### Utilities
- **anyhow** (v1.0.18) - Error handling
- **thiserror** (v1-2) - Error type definitions
- **tokio** (v1.13.1) - Async runtime
- **chrono** (v0.4) - Date/time handling
- **toml_edit** (v0.22) - TOML configuration editing
- **rusqlite** (v0.31-0.32) - SQLite database

### Testing
- **assert_cmd** (v2) - CLI testing
- **predicates** (v2-3) - Test assertions
- **subplotlib** (v0.11-0.12, optional) - Subplot framework

## Feature Flags

### Cryptographic Backends

Choose ONE crypto backend (library and tool inherit from workspace):

- **crypto-nettle** (default on Linux/Unix) - Nettle cryptographic library
- **crypto-openssl** - OpenSSL backend
- **crypto-botan** - Botan backend
- **crypto-botan2** - Botan 2 backend
- **crypto-cng** (default on Windows) - Windows CNG backend
- **crypto-rust** - Pure Rust cryptography

### Additional Features

- **clap** (library) - Enables clap integration for library types
- **subplot** (tool) - Enables subplot test generation

Example:
```bash
# Build with OpenSSL backend
cargo build --no-default-features --features crypto-openssl

# Build with subplot tests
cargo build --features subplot
```

## Code Organization Conventions

### Module Structure

1. **Library (`lib/src/`)**
   - Each major operation has its own module: `encrypt.rs`, `decrypt.rs`, `sign.rs`, `verify.rs`
   - Configuration is centralized in `config/` module
   - Types are organized in `types/` with one file per type
   - Unit tests are co-located with code using `#[cfg(test)]`

2. **Tool (`tool/src/`)**
   - `cli/` defines command-line structure (uses clap derive macros)
   - `commands/` implements command logic
   - `common/` contains shared utilities
   - `output/` handles output formatting
   - Separation of concerns: CLI definition vs. implementation

### File Naming Conventions

- Module files: lowercase with underscores (e.g., `cipher_suite.rs`)
- Test files: `sq_<command>.rs` pattern (e.g., `sq_encrypt.rs`)
- Integration tests use snake_case
- Each test module focuses on a specific command or feature

### Code Style

- Follow standard Rust formatting (use `cargo fmt`)
- Comprehensive documentation comments (`///` for public items)
- Error handling uses `anyhow::Result` for applications, custom errors for library
- Builder pattern used extensively (see `builder.rs`)
- Prefer explicit over implicit

## Testing Conventions

### Test Organization

1. **Unit Tests**
   - Located inline with code using `#[cfg(test)]` modules
   - Found in 8+ library source files
   - Test internal implementation details

2. **Integration Tests**
   - Located in `tool/tests/integration/`
   - 44+ test modules covering all CLI commands
   - Use `assert_cmd` crate for CLI testing
   - Pattern: `sq_<command>.rs`

3. **Subplot Tests**
   - Acceptance/BDD-style tests in `tool/sq-subplot.md`
   - Human-readable specification + executable tests
   - Generated code in `tests/sq-subplot.rs`
   - Requires `subplot` feature flag

### Test Data

- Test keys and keyrings: `tool/tests/data/keyrings/`
- Sample messages: `tool/tests/data/messages/`
- Real-world examples: `tool/tests/data/examples/`
- Autocrypt test data: `tool/tests/data/autocrypt/`

### Common Test Utilities

See `tool/tests/integration/common.rs`:

```rust
// Common test constants
pub const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
pub const NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };

// Helper functions
pub fn manifest_dir() -> PathBuf { ... }
pub fn artifact(filename: &str) -> PathBuf { ... }
```

### Writing Integration Tests

```rust
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_sq_command() {
    let mut cmd = Command::cargo_bin("sq").unwrap();
    cmd.arg("subcommand")
       .assert()
       .success()
       .stdout(predicate::str::contains("expected output"));
}
```

## Build System

### Build Script (`tool/build.rs`)

The build script performs several critical tasks:

1. **Shell Completion Generation**
   - Generates bash, fish, zsh completions
   - Output to `ASSET_OUT_DIR/shell-completions/` if set

2. **Man Page Generation**
   - Uses `sequoia-man` crate
   - Generates from clap CLI definitions
   - Output to `ASSET_OUT_DIR/man-pages/` if set

3. **Help Text Linting**
   - Validates short vs. long help consistency
   - Build fails if help texts don't meet standards
   - Ensures documentation quality

4. **Subplot Code Generation** (if feature enabled)
   - Generates test code from `sq.subplot`
   - Creates executable tests from specifications

### Environment Variables

- **ASSET_OUT_DIR** - Custom output directory for generated assets
- **SEQUOIA_HOME** - Override default sequoia state directory
- **SEQUOIA_CRYPTO_POLICY** - Set crypto policy (empty in CI)

### Cargo Profile Optimizations

The workspace Cargo.toml includes critical optimizations:

```toml
[profile.release]
debug = true

# Crypto crates are optimized even in dev builds (opt-level = 2)
# Includes: aes, blake2, ed25519, rsa, sha2, etc.
```

**Rationale:** Rust crypto crates are extremely slow without optimization. Development builds optimize crypto crates at `-O2` while keeping other code unoptimized for faster compilation.

## CI/CD Pipeline

### GitLab CI Configuration (`.gitlab-ci.yml`)

**Stages:**
1. `pre-check` - Pre-build validation
2. `build` - Compilation and artifact generation
3. `test` - Test execution
4. `deploy` - Deployment tasks

### Key CI Jobs

#### 1. Container Build & Push (`container-build-push`)
- Builds OCI image using Podman
- Runs smoke test (`sq --help`)
- Pushes to GitLab Registry
- Triggers: branches with 'docker', tags, web, schedules

#### 2. Pages Documentation (`pages`)
- Generates API docs: `cargo doc --no-deps -p sequoia-sq`
- Generates man pages (HTML format)
- Generates Subplot docs (HTML, PDF)
- Creates redirect rules

#### 3. Shared Sequoia CI
- Includes common pipeline: `gitlab.com/sequoia-pgp/common-ci/sequoia-pipeline@main`
- Extra features: `subplot`
- Runs standard Sequoia test suite

### CI Environment

- **Base Image:** Debian Trixie (testing)
- **Documentation Tools:** Pandoc for Subplot docs
- **Container Runtime:** Podman
- **Artifact Publishing:** GitLab Pages, Container Registry

## Important Files Reference

| File | Purpose | Size/Lines |
|------|---------|-----------|
| `Cargo.toml` | Workspace manifest | 95 lines |
| `lib/Cargo.toml` | Library dependencies | 76 lines |
| `tool/Cargo.toml` | Tool dependencies | 115 lines |
| `.gitlab-ci.yml` | CI/CD configuration | 84 lines |
| `lib/src/lib.rs` | Library entry point | Main API surface |
| `tool/src/main.rs` | CLI entry point | 17KB |
| `tool/src/sq.rs` | CLI command structure | 51KB |
| `tool/build.rs` | Build script | 163 lines |
| `openpgp-policy.toml` | OpenPGP policy config | Policy definitions |
| `tool/sq-subplot.md` | Acceptance criteria | 52KB |

## Common Workflows

### Adding a New CLI Command

1. Define CLI structure in `tool/src/cli/<module>.rs` using clap derive
2. Implement logic in `tool/src/commands/<module>.rs`
3. Add output formatting in `tool/src/output/<module>.rs` if needed
4. Add integration test in `tool/tests/integration/sq_<command>.rs`
5. Update help texts (will be linted at build time)
6. Optionally add Subplot acceptance tests

### Adding a Library Function

1. Add function to appropriate module in `lib/src/`
2. Add inline documentation comments
3. Add unit tests in `#[cfg(test)]` module
4. Export from `lib/src/lib.rs` if public
5. Update clap integration if needed (with `clap` feature)

### Updating Dependencies

1. Edit appropriate `Cargo.toml` (workspace, lib, or tool)
2. Run `cargo update` to update `Cargo.lock`
3. Test thoroughly: `cargo test --all-features`
4. Check for breaking changes
5. Update MSRV if needed (currently 1.85)

### Running Specific Tests

```bash
# Single integration test
cargo test --test integration sq_encrypt

# All cert-related tests
cargo test --test integration sq_cert

# Subplot tests
cargo test --features subplot

# Test with specific crypto backend
cargo test --no-default-features --features crypto-openssl
```

## Guidelines for AI Assistants

### When Making Code Changes

1. **Always Read First**
   - Never propose changes to code you haven't read
   - Understand existing patterns before modifying

2. **Follow Existing Patterns**
   - Match the style of surrounding code
   - Use established error handling patterns
   - Follow module organization conventions

3. **Security Awareness**
   - This is cryptographic software - security is paramount
   - Never introduce command injection, XSS, or other OWASP top 10 vulnerabilities
   - Be cautious with user input validation
   - Follow established key handling patterns

4. **Testing is Mandatory**
   - Add tests for new functionality
   - Update tests when changing behavior
   - Run `cargo test` before proposing changes
   - Consider both unit and integration tests

5. **Documentation Standards**
   - Add doc comments for public APIs
   - Help texts will be linted - follow existing format
   - Update man pages if changing CLI structure
   - Consider Subplot acceptance criteria updates

### Code Quality Expectations

1. **Build Must Pass**
   - `cargo build` must succeed
   - `cargo test` must pass
   - Help text linting must pass
   - No new compiler warnings

2. **Formatting**
   - Run `cargo fmt` before committing
   - Follow Rust naming conventions
   - Use idiomatic Rust patterns

3. **Error Handling**
   - Use `anyhow::Result` in application code
   - Provide context with `.context()`
   - Custom error types for library code
   - Meaningful error messages for users

4. **Performance Considerations**
   - This is a CLI tool - reasonable performance expected
   - Don't over-optimize prematurely
   - Crypto operations are already optimized (see Cargo.toml profiles)

### Understanding the Codebase

1. **Library vs. Tool**
   - `lib/` = reusable library for other applications
   - `tool/` = end-user command-line tool
   - Tool depends on library
   - Library should not depend on tool

2. **Crypto Backends**
   - Multiple backends supported via feature flags
   - Default: Nettle (Linux/Unix), CNG (Windows)
   - Tests run with appropriate backend for platform
   - Only one backend active at a time

3. **Policy System**
   - OpenPGP operations governed by policy (`openpgp-policy.toml`)
   - StandardPolicy used in production
   - NullPolicy used in some tests
   - Policy affects what operations are allowed

4. **Clap Integration**
   - Library types can work with clap when `clap` feature enabled
   - Avoids orphan rule issues
   - CLI definitions use clap derive macros
   - Help text generation is automatic

### Common Pitfalls to Avoid

1. **Don't Break MSRV**
   - Must compile on Rust 1.85
   - Avoid newer language features
   - Check feature compatibility

2. **Don't Mix Crypto Backends**
   - Only one backend should be active
   - Use feature flags correctly
   - Don't depend on specific backend unless necessary

3. **Don't Skip Help Text**
   - All CLI commands need help text
   - Short and long help should be consistent
   - Build will fail if help text doesn't pass linting

4. **Don't Ignore Test Data**
   - Test data is carefully curated
   - Real PGP keys and messages
   - Don't modify without understanding impact

5. **Don't Bypass Security Checks**
   - Policy enforcement is intentional
   - Certificate validation is critical
   - Don't shortcut crypto operations

### Useful Commands for Development

```bash
# Check compilation without building
cargo check

# Check all feature combinations
cargo check --all-features
cargo check --no-default-features

# Format code
cargo fmt

# Lint code
cargo clippy

# Build documentation
cargo doc --no-deps --open

# Run specific test with output
cargo test sq_encrypt -- --nocapture

# Build and inspect assets
ASSET_OUT_DIR=/tmp/assets cargo build
ls -R /tmp/assets

# Container smoke test
podman build -f tool/Containerfile -t sq-test .
podman run --rm sq-test --version
```

### When to Ask for Clarification

1. **Security-sensitive changes** - Always verify security implications
2. **Crypto backend changes** - Confirm intended backend behavior
3. **Breaking API changes** - Check if breaking changes are acceptable
4. **MSRV impacts** - Verify if newer Rust features are worth raising MSRV
5. **Policy changes** - Understand implications of policy modifications

## Resources

- **Official Documentation:** https://sequoia-pgp.gitlab.io/user-documentation
- **Man Pages:** https://sequoia-pgp.gitlab.io/sequoia-sq/man/
- **Acceptance Criteria:** https://sequoia-pgp.gitlab.io/sequoia-sq/subplot/
- **API Documentation:** https://sequoia-pgp.gitlab.io/sequoia-sq/impl/
- **Sequoia-PGP Homepage:** https://sequoia-pgp.org/
- **Repository:** https://gitlab.com/sequoia-pgp/sequoia-sq

## Contribution Workflow

While this repository doesn't have a CONTRIBUTING.md, follow these practices:

1. **Branch Management**
   - Work on feature branches
   - Follow any branch naming conventions
   - Keep commits focused and logical

2. **Commit Messages**
   - Clear, descriptive messages
   - Reference issues if applicable
   - Explain "why" not just "what"

3. **Testing**
   - Run full test suite before pushing
   - Add tests for new features
   - Update tests for bug fixes

4. **CI Pipeline**
   - Ensure CI passes before merging
   - Check container builds if relevant
   - Verify documentation generation

## Project Metadata

- **Authors:** Azul, Heiko Schaefer, Igor Matuszewski, Justus Winter, Kai Michaelis, Lars Wirzenius, Neal H. Walfield, Nora Widdecke, Wiktor Kwapisiewicz
- **Maintenance Status:** Actively Developed
- **Current Version:**
  - Library: 0.1.0
  - Tool: 1.3.1
- **Rust Edition:** 2021
- **MSRV:** 1.85

---

**Note for AI Assistants:** This document is maintained to help you understand and work effectively with the Sequoia-SQ codebase. When in doubt, consult existing code patterns, test thoroughly, and prioritize security and correctness over cleverness.
