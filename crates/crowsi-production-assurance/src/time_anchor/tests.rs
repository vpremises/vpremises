//! Focused regression cases for the enclosing implementation.
use super::DurableTimeAnchor;

#[test]
fn rollback_is_rejected_after_reopen() {
    let root = tempfile::tempdir().expect("temporary root");
    let path = root.path().join("clock.sqlite3");
    DurableTimeAnchor::open(&path)
        .expect("first open")
        .observe(101)
        .expect("first observation");

    let mut reopened = DurableTimeAnchor::open(&path).expect("reopen");
    assert!(reopened.observe(100).is_err());
    reopened.observe(101).expect("equal time remains valid");
}
