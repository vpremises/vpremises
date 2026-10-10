use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn trusted_now_epoch_s() -> Option<u64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}
