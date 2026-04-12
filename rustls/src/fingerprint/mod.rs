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
