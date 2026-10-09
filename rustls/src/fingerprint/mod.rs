//! TLS fingerprint profiles for browser impersonation.
//!
//! Allows configuring `ClientConfig` to produce ClientHello messages that match
//! specific browser TLS fingerprints (cipher suites, extension order, GREASE).

mod profiles;
pub use profiles::*;

use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::{ExtensionType, NamedGroup};

/// A TLS fingerprint profile that controls ClientHello construction.
///
/// Profiles specify:
/// - Which extensions to include and their encoding order
/// - Cipher suite list and order
/// - Named group preferences
/// - Signature scheme preferences
/// - Whether to inject GREASE values
#[derive(Clone, Debug)]
pub struct Fingerprint {
    /// The display name of this profile (e.g., "chrome-134").
    pub name: &'static str,
    /// Cipher suites in wire order. GREASE values (0x_a_a) can be included.
    ///
    /// NOTE: These are for the wire format only, not for negotiation. Some suites
    /// (e.g. CBC, RSA-only) may not be supported by the active `CryptoProvider`.
    /// They are included so the ClientHello fingerprint matches the real browser.
    /// The actual negotiation will only succeed with provider-supported suites.
    pub cipher_suites: &'static [CipherSuite],
    /// Extension types in wire order. GREASE placeholders use ExtensionType::Unknown(0x_a_a).
    pub extensions: &'static [ExtensionType],
    /// Named groups in preference order.
    pub named_groups: &'static [NamedGroup],
    /// Signature schemes in preference order.
    pub signature_schemes: &'static [SignatureScheme],
    /// Whether to inject GREASE values at the positions marked in cipher_suites/extensions.
    pub grease: bool,
    /// Whether to randomize extension order within the non-fixed portion.
    /// Chrome does this since 2023; Firefox/Safari do not.
    pub shuffle_extensions: bool,
}

/// Builder for applying a fingerprint to a ClientConfig.
#[derive(Clone, Debug)]
pub struct FingerprintConfig {
    pub(crate) fingerprint: &'static Fingerprint,
    pub(crate) override_alpn: bool,
}

impl Fingerprint {
    /// Create a FingerprintConfig from this profile.
    pub fn config(&'static self) -> FingerprintConfig {
        FingerprintConfig {
            fingerprint: self,
            override_alpn: true,
        }
    }
}

impl FingerprintConfig {
    /// Don't override ALPN (useful when hyper/h2 manage ALPN themselves).
    pub fn preserve_alpn(mut self) -> Self {
        self.override_alpn = false;
        self
    }
}

#[cfg(all(test, feature = "ring", feature = "std"))]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use super::INSTAGRAM_MNS;
    use crate::{ClientConfig, ClientConnection, RootCertStore};

    /// Parsed view of the first ClientHello a config emits.
    struct Hello {
        legacy_version: u16,
        ciphers: Vec<u16>,
        ext_order: Vec<u16>,
        ext_data: Vec<(u16, Vec<u8>)>,
    }

    fn be16(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }

    fn first_client_hello(config: ClientConfig) -> Hello {
        let name = "b.i.instagram.com".try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
        let mut wire = Vec::new();
        conn.write_tls(&mut wire).unwrap();
        // record header (5) + handshake header (4)
        assert_eq!(wire[0], 0x16, "handshake record");
        assert_eq!(wire[5], 0x01, "client_hello");
        let mut p = 9;
        let legacy_version = be16(&wire[p..]);
        p += 2 + 32; // version + random
        let sid_len = wire[p] as usize;
        p += 1 + sid_len;
        let cs_len = be16(&wire[p..]) as usize;
        p += 2;
        let ciphers: Vec<u16> = wire[p..p + cs_len].chunks(2).map(be16).collect();
        p += cs_len;
        let comp_len = wire[p] as usize;
        p += 1 + comp_len;
        let ext_len = be16(&wire[p..]) as usize;
        p += 2;
        let end = p + ext_len;
        let mut ext_order = Vec::new();
        let mut ext_data = Vec::new();
        while p < end {
            let kind = be16(&wire[p..]);
            let len = be16(&wire[p + 2..]) as usize;
            ext_order.push(kind);
            ext_data.push((kind, wire[p + 4..p + 4 + len].to_vec()));
            p += 4 + len;
        }
        Hello { legacy_version, ciphers, ext_order, ext_data }
    }

    /// The profile must reproduce the Instagram Android app's ClientHello
    /// exactly (JA3 `771,4865,0-43-10-51-13-16-45,29-23,`): anything else
    /// draws an empty-body HTTP 429 at the CAA credential submit.
    #[test]
    fn instagram_mns_profile_matches_the_app_wire_shape() {
        let provider = Arc::new(crate::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&crate::version::TLS13])
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
            .with_fingerprint(INSTAGRAM_MNS.config());
        config.alpn_protocols = alloc::vec![b"h2".to_vec()];

        let hello = first_client_hello(config);
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.ciphers, alloc::vec![0x1301]);
        assert_eq!(hello.ext_order, alloc::vec![0, 43, 10, 51, 13, 16, 45]);
        let ext = |k: u16| &hello.ext_data.iter().find(|(kind, _)| *kind == k).unwrap().1;
        assert_eq!(ext(43), &[0x02, 0x03, 0x04], "TLS 1.3 only");
        assert_eq!(ext(10), &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17], "X25519, P-256");
        assert_eq!(ext(13), &[0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04]);
        assert_eq!(&ext(51)[..6], &[0x00, 0x24, 0x00, 0x1d, 0x00, 0x20], "one X25519 key share");
        assert_eq!(ext(51).len(), 2 + 4 + 32, "exactly one key share");
        assert_eq!(ext(16), b"\x00\x03\x02h2", "ALPN h2 only");
    }
}
