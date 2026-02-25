//! Resilience tests: corrupted files, wrong passphrases, tampered data.

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::storage::{load_identity, save_identity};

#[test]
fn resilience_corrupted_aid_file_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("corrupted.aid");

    let anchor = IdentityAnchor::new(Some("corruption-test".to_string()));
    save_identity(&anchor, &path, "test_pass").unwrap();

    // Corrupt the file by flipping bytes in the middle
    {
        let mut data = std::fs::read(&path).unwrap();
        if data.len() > 50 {
            for item in data.iter_mut().take(50).skip(40) {
                *item ^= 0xFF;
            }
        }
        std::fs::write(&path, data).unwrap();
    }

    let result = load_identity(&path, "test_pass");
    assert!(result.is_err(), "Corrupted file should fail to load");
}

#[test]
fn resilience_wrong_passphrase_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("passphrase-test.aid");

    let anchor = IdentityAnchor::new(Some("passphrase-test".to_string()));
    save_identity(&anchor, &path, "correct_password").unwrap();

    let result = load_identity(&path, "wrong_password");
    assert!(result.is_err(), "Wrong passphrase should fail");
}

#[test]
fn resilience_truncated_file_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("truncated.aid");

    let anchor = IdentityAnchor::new(Some("truncation-test".to_string()));
    save_identity(&anchor, &path, "test_pass").unwrap();

    // Truncate the file
    {
        let data = std::fs::read(&path).unwrap();
        let half = data.len() / 2;
        std::fs::write(&path, &data[..half]).unwrap();
    }

    let result = load_identity(&path, "test_pass");
    assert!(result.is_err(), "Truncated file should fail to load");
}

#[test]
fn resilience_empty_file_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("empty.aid");

    std::fs::write(&path, b"").unwrap();

    let result = load_identity(&path, "test_pass");
    assert!(result.is_err(), "Empty file should fail to load");
}

#[test]
fn resilience_nonexistent_file() {
    let result = load_identity(
        std::path::Path::new("/tmp/definitely_does_not_exist_12345.aid"),
        "test_pass",
    );
    assert!(result.is_err(), "Nonexistent file should fail");
}

#[test]
fn resilience_save_creates_parent_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let deep_path = tmp.path().join("a").join("b").join("c").join("deep.aid");

    let anchor = IdentityAnchor::new(Some("deep-save".to_string()));
    let result = save_identity(&anchor, &deep_path, "test_pass");
    assert!(result.is_ok(), "Should create parent directories");

    let loaded = load_identity(&deep_path, "test_pass").unwrap();
    assert_eq!(loaded.id(), anchor.id());
}

#[test]
fn resilience_identity_roundtrip_100_times() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("roundtrip.aid");

    for i in 0..100 {
        let anchor = IdentityAnchor::new(Some(format!("roundtrip-{i}")));
        save_identity(&anchor, &path, "pass").unwrap();
        let loaded = load_identity(&path, "pass").unwrap();
        assert_eq!(loaded.id(), anchor.id(), "Roundtrip {i} failed");
    }
}

#[test]
fn resilience_random_bytes_not_valid_aid() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("random.aid");

    let random_data: Vec<u8> = (0..1024).map(|i| (i * 17 + 31) as u8).collect();
    std::fs::write(&path, &random_data).unwrap();

    let result = load_identity(&path, "test_pass");
    assert!(
        result.is_err(),
        "Random bytes should not be a valid .aid file"
    );
}
