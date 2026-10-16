//! Integration tests against a real qqwry database.
//!
//! The database is large, so tests use `data/qqwry.dat` when present and only
//! fall back to downloading it into the temporary directory. They are ignored
//! by default; run them with:
//!
//! ```text
//! cargo test --test lookup -- --ignored
//! ```
//!
//! Set `QQWRY_DB` to point at a specific database, which is what CI does after
//! downloading `qqwry.dat`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use qqwry::{LookupError, Qqwry};

const DATABASE_URL: &str =
    "https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat";

/// Locates the database: `$QQWRY_DB`, then `data/qqwry.dat`, then a download.
///
/// The result is computed once per process so that parallel tests do not race
/// to download the same file.
fn database_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();

    PATH.get_or_init(|| {
        if let Some(path) = std::env::var_os("QQWRY_DB") {
            return PathBuf::from(path);
        }

        let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/qqwry.dat");
        if local.exists() {
            return local;
        }

        download_database()
    })
    .clone()
}

/// Downloads the database into the temporary directory and caches it there.
fn download_database() -> PathBuf {
    let path = std::env::temp_dir().join("qqwry-test.dat");
    if path.exists() {
        return path;
    }

    let bytes = ureq::get(DATABASE_URL)
        .call()
        .expect("download qqwry.dat")
        .body_mut()
        .with_config()
        .limit(128 * 1024 * 1024)
        .read_to_vec()
        .expect("read qqwry.dat body");

    std::fs::write(&path, &bytes).expect("write qqwry.dat");
    path
}

#[test]
#[ignore = "requires a qqwry database"]
fn looks_up_known_addresses() {
    let qqwry = Qqwry::new(database_path()).expect("open database");

    for ip in ["8.8.8.8", "1.1.1.1", "114.114.114.114"] {
        let (location, isp) = qqwry
            .lookup(ip)
            .unwrap_or_else(|error| panic!("{ip}: {error}"));
        assert!(!location.is_empty(), "{ip} has no location");
        assert!(!isp.is_empty(), "{ip} has no isp");
    }
}

#[test]
#[ignore = "requires a qqwry database"]
fn the_database_also_covers_reserved_space() {
    let qqwry = Qqwry::new(database_path()).expect("open database");

    // The qqwry database maps every IPv4 range, including reserved space,
    // which it labels with the responsible registry.
    for ip in ["127.0.0.1", "10.0.0.1", "192.0.2.1"] {
        let (location, _) = qqwry
            .lookup(ip)
            .unwrap_or_else(|error| panic!("{ip}: {error}"));
        assert!(!location.is_empty(), "{ip} has no location");
    }
}

/// The qqwry database is contiguous and covers `0.0.0.1` through
/// `255.255.255.255`, so any sampled address should resolve.
#[test]
#[ignore = "requires a qqwry database"]
fn a_sample_across_the_whole_space_resolves() {
    let qqwry = Qqwry::new(database_path()).expect("open database");

    // xorshift32 keeps the sample deterministic without a `rand` dependency.
    let mut state = 0x9E37_79B9u32;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;

        if state == 0 {
            continue; // 0.0.0.0 is the one address the database omits
        }

        let ip = Ipv4Addr::from(state);
        assert!(
            qqwry.lookup_ip(ip).is_ok(),
            "{ip} should be covered by the database"
        );
    }
}

#[test]
#[ignore = "requires a qqwry database"]
fn a_truncated_database_is_reported_not_panicked_on() {
    let database = std::fs::read(database_path()).expect("read database");
    let path = std::env::temp_dir().join("qqwry-test-truncated.dat");

    let mut reported = false;
    for divisor in [2, 4, 8, 16] {
        std::fs::write(&path, &database[..database.len() / divisor]).expect("write truncated copy");

        match Qqwry::new(&path).map(|qqwry| qqwry.lookup("8.8.8.8")) {
            Ok(Ok(_)) => {}
            Ok(Err(LookupError::Malformed | LookupError::NotFound)) | Err(_) => reported = true,
            Ok(Err(other)) => panic!("unexpected lookup error: {other}"),
        }
    }

    assert!(
        reported,
        "a truncated database must be reported as an error"
    );
}

#[test]
#[ignore = "requires a qqwry database"]
fn the_cli_prints_location_and_isp() {
    let output = Command::new(env!("CARGO_BIN_EXE_qqwry"))
        .arg(database_path())
        .arg("8.8.8.8")
        .output()
        .expect("run the qqwry binary");

    assert!(output.status.success(), "the cli should exit successfully");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(
        stdout.contains(", "),
        "expected `location, isp`, got {stdout:?}"
    );
}

#[test]
#[ignore = "requires a qqwry database"]
fn the_cli_reports_invalid_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_qqwry"))
        .arg(database_path())
        .arg("not-an-ip")
        .output()
        .expect("run the qqwry binary");

    assert!(!output.status.success(), "invalid input should fail");
    assert!(
        !output.stderr.is_empty(),
        "the failure should be explained on stderr"
    );
}
