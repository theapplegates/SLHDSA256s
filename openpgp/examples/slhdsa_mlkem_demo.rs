/// Demonstrates V6 certificate generation with post-quantum cryptography
///
/// This example generates an OpenPGP V6 certificate using:
/// - Primary key: SLHDSA256s (certification + signing)
/// - Signing subkey: SLHDSA256s
/// - Encryption subkey: MLKEM1024_X448
///
/// Requirements:
/// - OpenSSL backend with PQC support (OpenSSL 3.x or higher)
/// - Build with: cargo build --no-default-features --features crypto-openssl,compression
///
/// Usage:
///   cargo run --example slhdsa_mlkem_demo --no-default-features \
///     --features crypto-openssl,compression -- "Your Name" "you@example.com"

use std::env;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::types::{KeyFlags, PublicKeyAlgorithm};
use openpgp::Profile;
use openpgp::serialize::Serialize;
use openpgp::armor::{Writer as ArmorWriter, Kind};
use openpgp::policy::StandardPolicy;

fn main() -> openpgp::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse command-line arguments
    let (name, email) = if args.len() >= 3 {
        (args[1].as_str(), args[2].as_str())
    } else {
        println!("Usage: {} <name> <email>", args.get(0).unwrap_or(&"slhdsa_mlkem_demo".to_string()));
        println!("\nGenerating example certificate with default values...\n");
        ("Example User", "user@example.com")
    };

    let userid = format!("{} <{}>", name, email);

    println!("=== Post-Quantum Certificate Generation ===");
    println!("User ID: {}", userid);
    println!("Profile: V6 (RFC 9580)");
    println!("Primary key: SLHDSA256s (certification + signing)");
    println!("Signing subkey: SLHDSA256s");
    println!("Encryption subkey: MLKEM1024_X448");
    println!();

    // Check if algorithms are supported
    if !PublicKeyAlgorithm::SLHDSA256s.is_supported() {
        eprintln!("ERROR: SLHDSA256s is not supported by this crypto backend.");
        eprintln!("Please build with OpenSSL backend:");
        eprintln!("  cargo build --no-default-features --features crypto-openssl,compression");
        return Err(openpgp::Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::SLHDSA256s
        ).into());
    }

    if !PublicKeyAlgorithm::MLKEM1024_X448.is_supported() {
        eprintln!("ERROR: MLKEM1024_X448 is not supported by this crypto backend.");
        eprintln!("Please build with OpenSSL backend:");
        eprintln!("  cargo build --no-default-features --features crypto-openssl,compression");
        return Err(openpgp::Error::UnsupportedPublicKeyAlgorithm(
            PublicKeyAlgorithm::MLKEM1024_X448
        ).into());
    }

    println!("✓ Crypto backend supports SLHDSA256s");
    println!("✓ Crypto backend supports MLKEM1024_X448");
    println!();

    // Generate the certificate
    println!("Generating certificate...");
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(userid.as_str())
        .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        // Set SLHDSA256s for all signing operations
        .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)?
        // Set MLKEM1024_X448 for all encryption operations
        .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)?
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .generate()?;

    println!("✓ Certificate generated successfully");
    println!();

    // Display certificate information
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None)?;

    println!("=== Certificate Information ===");
    println!("Fingerprint: {}", cert.fingerprint());
    println!("Version: {}", cert.primary_key().key().version());
    println!();

    println!("Primary key:");
    println!("  Algorithm: {:?}", cert.primary_key().key().pk_algo());
    println!("  Key flags: {:?}", vc.primary_key().key_flags());
    println!();

    println!("Subkeys:");
    for (i, ka) in vc.keys().subkeys().enumerate() {
        println!("  Subkey {}:", i + 1);
        println!("    Algorithm: {:?}", ka.key().pk_algo());
        if let Some(flags) = ka.key_flags() {
            println!("    Key flags: {:?}", flags);
        }
        println!();
    }

    // Verify the key structure
    println!("=== Verification ===");

    // Check primary key
    let primary_algo = cert.primary_key().key().pk_algo();
    if primary_algo == PublicKeyAlgorithm::SLHDSA256s {
        println!("✓ Primary key: SLHDSA256s");
    } else {
        println!("✗ Primary key: {:?} (expected SLHDSA256s)", primary_algo);
    }

    // Check subkeys
    let subkeys: Vec<_> = vc.keys().subkeys().collect();

    if subkeys.len() >= 2 {
        // First subkey should be signing (SLHDSA256s)
        let signing_subkey = &subkeys[0];
        let signing_algo = signing_subkey.key().pk_algo();
        if signing_algo == PublicKeyAlgorithm::SLHDSA256s {
            println!("✓ Signing subkey: SLHDSA256s");
        } else {
            println!("✗ Signing subkey: {:?} (expected SLHDSA256s)", signing_algo);
        }

        // Second subkey should be encryption (MLKEM1024_X448)
        let encryption_subkey = &subkeys[1];
        let encryption_algo = encryption_subkey.key().pk_algo();
        if encryption_algo == PublicKeyAlgorithm::MLKEM1024_X448 {
            println!("✓ Encryption subkey: MLKEM1024_X448");
        } else {
            println!("✗ Encryption subkey: {:?} (expected MLKEM1024_X448)", encryption_algo);
        }
    } else {
        println!("✗ Expected at least 2 subkeys, found {}", subkeys.len());
    }

    println!();

    // Export keys to files
    let safe_name = name.replace(" ", "_");
    let public_file = format!("{}_public.asc", safe_name);
    let secret_file = format!("{}_secret.asc", safe_name);

    println!("=== Exporting Keys ===");

    // Export public key
    {
        let mut public_writer = ArmorWriter::new(
            std::fs::File::create(&public_file)?,
            Kind::PublicKey
        )?;
        cert.serialize(&mut public_writer)?;
        public_writer.finalize()?;
    }

    let public_size = std::fs::metadata(&public_file)?.len();
    println!("✓ Public key exported: {} ({} bytes)", public_file, public_size);

    // Export secret key
    {
        let mut secret_writer = ArmorWriter::new(
            std::fs::File::create(&secret_file)?,
            Kind::SecretKey
        )?;
        cert.as_tsk().serialize(&mut secret_writer)?;
        secret_writer.finalize()?;
    }

    let secret_size = std::fs::metadata(&secret_file)?.len();
    println!("✓ Secret key exported: {} ({} bytes)", secret_file, secret_size);

    println!();
    println!("=== Summary ===");
    println!("Successfully generated V6 certificate with post-quantum cryptography:");
    println!("  • Primary: SLHDSA256s (certification + signing)");
    println!("  • Subkey 1: SLHDSA256s (signing)");
    println!("  • Subkey 2: MLKEM1024_X448 (encryption)");
    println!();
    println!("Note: Large key sizes (~200KB) are expected for post-quantum algorithms.");

    Ok(())
}
