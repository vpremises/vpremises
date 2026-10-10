use crowsi_control_contracts::SignedDigestV1;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"crowsi-incident-canonical-v1\0";

pub trait IncidentCanonicalPayloadV1 {
    #[must_use]
    fn signing_payload(&self) -> Vec<u8>;

    #[doc(hidden)]
    fn signed_digest(&self) -> &SignedDigestV1;

    #[must_use]
    fn payload_digest(&self) -> String {
        digest_payload(&self.signing_payload())
    }

    #[must_use]
    fn payload_digest_matches(&self) -> bool {
        self.payload_digest() == self.signed_digest().digest
    }
}

pub(crate) fn digest_payload(payload: &[u8]) -> String {
    let hash = Sha256::digest(payload);
    let alphabet = b"0123456789abcdef";
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in hash {
        value.push(alphabet[usize::from(byte >> 4)] as char);
        value.push(alphabet[usize::from(byte & 0x0f)] as char);
    }
    value
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(artifact: &str) -> Self {
        let mut value = Self {
            bytes: DOMAIN.to_vec(),
        };
        value.text("artifact", artifact);
        value
    }

    pub(crate) fn text(&mut self, name: &str, value: &str) {
        self.bytes(name, value.as_bytes());
    }

    pub(crate) fn number(&mut self, name: &str, value: u64) {
        self.bytes(name, &value.to_be_bytes());
    }

    pub(crate) fn optional_text(&mut self, name: &str, value: Option<&str>) {
        self.bytes(&format!("{name}.present"), &[u8::from(value.is_some())]);
        if let Some(value) = value {
            self.text(name, value);
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn bytes(&mut self, name: &str, value: &[u8]) {
        let name = name.as_bytes();
        let name_length = u16::try_from(name.len()).expect("canonical field name fits u16");
        let value_length = u64::try_from(value.len()).expect("canonical field value fits u64");
        self.bytes.extend_from_slice(&name_length.to_be_bytes());
        self.bytes.extend_from_slice(name);
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }
}
