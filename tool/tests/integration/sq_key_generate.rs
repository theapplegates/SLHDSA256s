use std::time;

use sequoia::openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::parse::Parse;

use super::common;
use super::common::UserIDArg;
use super::common::NO_USERIDS;

#[test]
fn sq_key_generate_no_userid() -> Result<()> {
    let sq = common::Sq::new();

    // Stateless key generation.
    let (cert, _, _) = sq.key_generate::<&str>(&[], &[]);
    assert_eq!(cert.userids().count(), 0);

    // Stateful key generation.
    let mut cmd = sq.command();
    cmd.args(["key", "generate", "--own-key", "--no-userids",
              "--without-password"]);
    sq.run(cmd, true);

    Ok(())
}

#[test]
fn sq_key_generate_creation_time() -> Result<()>
{
    let sq = common::Sq::new();

    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let iso8601 = "20220120T163236+0100";
    let t = 1642692756;

    let (result, _, _) = sq.key_generate(&[
        "--time", iso8601,
        "--expiration", "never",
    ], NO_USERIDS);
    let vc = result.with_policy(common::STANDARD_POLICY, None)?;

    assert_eq!(vc.primary_key().key().creation_time(),
               time::UNIX_EPOCH + time::Duration::new(t, 0));
    assert!(vc.primary_key().key_expiration_time().is_none());

    Ok(())
}

#[test]
fn sq_key_generate_name_email() -> Result<()> {
    let sq = common::Sq::new();
    let (cert, _, _) = sq.key_generate(
        &[],
        &[
            UserIDArg::Name("Joan Clarke"),
            UserIDArg::Name("Joan Clarke Murray"),
            UserIDArg::Email("joan@hut8.bletchley.park"),
        ]);

    assert_eq!(cert.userids().count(), 3);
    assert!(cert.userids().any(|u| u.userid().value() == b"Joan Clarke"));
    assert!(cert.userids().any(|u| u.userid().value() == b"Joan Clarke Murray"));
    assert!(
        cert.userids().any(|u| u.userid().value() == b"<joan@hut8.bletchley.park>"));

    Ok(())
}

#[test]
fn sq_key_generate_with_password() -> Result<()> {
    let sq = common::Sq::new();

    let password = "hunter2";
    let path = sq.base().join("password");
    std::fs::write(&path, password)?;

    let (cert, _, _) = sq.key_generate(&[
        "--new-password-file", &path.display().to_string(),
    ], NO_USERIDS);

    assert!(cert.is_tsk());

    let password = password.into();
    for key in cert.keys() {
        let secret = key.key().optional_secret().unwrap();
        assert!(secret.is_encrypted());
        assert!(secret.clone().decrypt(key.key(), &password).is_ok());
    }

    Ok(())
}

// Make sure we can write to /dev/null.
#[cfg(unix)]
#[test]
fn sq_key_generate_dev_null() -> Result<()> {
    let sq = common::Sq::new();

    let cert_file = sq.scratch_file("cert");

    let mut cmd = sq.command();
    cmd.args([
        "key", "generate", "--own-key", "--no-userids",
        "--without-password",
        "--output", &cert_file.display().to_string(),
        "--rev-cert", "/dev/null",
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(cert_file).expect("Have a cert");

    Ok(())
}

// Make sure we can overwrite a file in a directory that is not
// writable.
#[cfg(unix)]
#[test]
fn sq_key_generate_overwrite() -> Result<()> {
    let sq = common::Sq::new();

    let dir = sq.scratch_dir();
    let cert_file = dir.join("cert.pgp");
    std::fs::write(&cert_file, "foo").expect("can write");
    let rev_file = dir.join("cert.rev");
    std::fs::write(&rev_file, "foo").expect("can write");

    // Remove the write bit.
    let metadata = std::fs::metadata(&dir).expect("can stat");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&dir, permissions)
        .expect("can chmod");

    // Make sure we can still write to the existing file, but we can't
    // create new files.
    std::fs::write(&cert_file, "foo").expect("can write");
    std::fs::write(dir.join("other"), "foo").expect_err("can't create");

    // Now overwrite cert.pgp.
    let mut cmd = sq.command();
    cmd.args([
        "key", "generate",
        "--overwrite",
        "--own-key", "--no-userids",
        "--without-password",
        "--output", &cert_file.display().to_string(),
        "--rev-cert", &rev_file.display().to_string(),
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(&cert_file).expect("Have a cert");

    // Check that the certificate was not appended to the existing
    // data.
    let content = std::fs::read(&cert_file).expect("Can read file");
    assert!(content.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"),
            "Expected an ASCII-armored key, but got: {:?}",
            String::from_utf8_lossy(&content));

    let _rev = Cert::from_file(&rev_file).expect("Have a cert");

    // Check that the certificate was not appended to the existing
    // data.
    let content = std::fs::read(&rev_file).expect("Can read file");
    assert!(content.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
            "Expected an ASCII-armored certificate, but got: {:?}",
            String::from_utf8_lossy(&content));

    Ok(())
}
