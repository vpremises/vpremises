# Evidence signing contract

`EvidencePayload::signing_bytes()` is a SHA-256 digest of a versioned,
length-prefixed binary representation. JSON bytes are never signed directly.

The representation starts with `CROWSI-PRODUCTION-EVIDENCE-V1` and a NUL byte,
then encodes fields in Rust struct order. Strings use an unsigned 64-bit
big-endian byte length followed by UTF-8 bytes. Times and freshness use unsigned
64-bit big-endian integers. Enum and assertion tags are the one-byte values
defined in `src/canonical.rs`; assertions are sorted by enum order.

Changing any target, deployment, security domain, evidence kind, time,
attestation assertion, subject digest, common assurance-context digest, or
freshness value therefore changes the signed digest. The common context is the
digest of the reviewed deployment evidence manifest; all seven independent
authorities must sign the same value so unrelated evidence cannot be spliced
into one bundle. The library recomputes that digest from the closed
`AssuranceContext`, including every evidence ID and digest, release, SBOM,
command, fence epoch, isolation drill, recovery drill and read-back. A future
contract revision must use a new prefix and schema identifier.
