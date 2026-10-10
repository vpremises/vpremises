use std::io::Read;

use crate::{BaselineV1, SensorError};

const MAX_BASELINE_BYTES: u64 = 65_536;

/// Reads one bounded baseline JSON value from a caller-supplied stream.
///
/// This is used for stdin only by the CLI; it never selects a filesystem path.
///
/// # Errors
///
/// Rejects read failures, oversized input, and invalid closed-contract JSON.
pub fn read_baseline(reader: impl Read) -> Result<BaselineV1, SensorError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BASELINE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SensorError::InputReadFailed)?;
    if bytes.len() as u64 > MAX_BASELINE_BYTES {
        return Err(SensorError::InputTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| SensorError::InvalidContract)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BASELINE_BYTES, read_baseline};
    use crate::{SensorError, sample_baseline};

    #[test]
    fn accepts_sample_and_rejects_unknown_fields() {
        let json = serde_json::to_vec(&sample_baseline().unwrap()).unwrap();
        assert!(read_baseline(json.as_slice()).is_ok());
        let source = String::from_utf8(json).unwrap();
        let changed = source.replacen('{', "{\"unexpected\":true,", 1);
        assert_eq!(
            read_baseline(changed.as_bytes()).unwrap_err(),
            SensorError::InvalidContract
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![b' '; usize::try_from(MAX_BASELINE_BYTES + 1).unwrap()];
        assert_eq!(
            read_baseline(bytes.as_slice()).unwrap_err(),
            SensorError::InputTooLarge
        );
    }
}
