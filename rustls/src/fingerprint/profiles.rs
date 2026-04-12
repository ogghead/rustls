//! Built-in browser fingerprint profiles.
//!
//! Each profile defines the exact cipher suite list, extension order, named groups,
//! and signature schemes that a specific browser version advertises in its ClientHello.

use super::Fingerprint;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::NamedGroup;
use crate::msgs::enums::ExtensionType;

// ---------------------------------------------------------------------------
// Chrome 134 (BoringSSL-based)
// ---------------------------------------------------------------------------

/// Cipher suites advertised by Chrome 134 in wire order.
///
/// NOTE: These are for fingerprint matching on the wire, NOT for negotiation.
/// Suites like CBC and RSA-only are not supported by rustls's crypto providers,
/// but real Chrome advertises them, so we include them for fingerprint fidelity.
/// The TLS handshake will only negotiate suites the active CryptoProvider supports.
static CHROME_134_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::Unknown(0x0A0A), // GREASE
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
];

/// Extension types advertised by Chrome 134 in wire order.
static CHROME_134_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::Unknown(0x0A0A),          // GREASE
    ExtensionType::ServerName,               // server_name (0x0000)
    ExtensionType::ExtendedMasterSecret,     // extended_master_secret (0x0017)
    ExtensionType::RenegotiationInfo,        // renegotiation_info (0xff01)
    ExtensionType::EllipticCurves,           // supported_groups (0x000a)
    ExtensionType::ECPointFormats,           // ec_point_formats (0x000b)
    ExtensionType::SessionTicket,            // session_ticket (0x0023)
    ExtensionType::ALProtocolNegotiation,    // application_layer_protocol_negotiation (0x0010)
    ExtensionType::StatusRequest,            // status_request (0x0005)
    ExtensionType::SignatureAlgorithms,      // signature_algorithms (0x000d)
    ExtensionType::SCT,                      // signed_certificate_timestamp (0x0012)
    ExtensionType::KeyShare,                 // key_share (0x0033)
    ExtensionType::PSKKeyExchangeModes,      // psk_key_exchange_modes (0x002d)
    ExtensionType::SupportedVersions,        // supported_versions (0x002b)
    ExtensionType::CompressCertificate,      // compress_certificate (0x001b)
    ExtensionType::Unknown(0x4A4A),          // GREASE
    ExtensionType::Padding,                  // padding (0x0015)
];

/// Named groups advertised by Chrome 134.
static CHROME_134_NAMED_GROUPS: &[NamedGroup] = &[
    NamedGroup::Unknown(0x0A0A), // GREASE
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
];

/// Signature schemes advertised by Chrome 134.
static CHROME_134_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// TLS fingerprint profile for Chrome 134.
///
/// Matches the ClientHello produced by Chrome 134 (BoringSSL). Enables GREASE
/// injection and extension shuffling, both of which Chrome has used since ~2023.
pub static CHROME_134: Fingerprint = Fingerprint {
    name: "chrome-134",
    cipher_suites: CHROME_134_CIPHER_SUITES,
    extensions: CHROME_134_EXTENSIONS,
    named_groups: CHROME_134_NAMED_GROUPS,
    signature_schemes: CHROME_134_SIGNATURE_SCHEMES,
    grease: true,
    shuffle_extensions: true,
};

// ---------------------------------------------------------------------------
// Firefox 128 (NSS-based)
// ---------------------------------------------------------------------------

/// Cipher suites advertised by Firefox 128 in wire order.
///
/// NOTE: These are for fingerprint matching on the wire, NOT for negotiation.
/// See the note on CHROME_134_CIPHER_SUITES for details.
static FIREFOX_128_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_128_GCM_SHA256,
    CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
];

/// Extension types advertised by Firefox 128 in wire order.
///
/// `delegated_credentials` (0x0022) and `record_size_limit` (0x001c) are not
/// named variants in rustls's `ExtensionType` enum, so we use `Unknown(...)`.
static FIREFOX_128_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::ServerName,               // server_name (0x0000)
    ExtensionType::ExtendedMasterSecret,     // extended_master_secret (0x0017)
    ExtensionType::RenegotiationInfo,        // renegotiation_info (0xff01)
    ExtensionType::EllipticCurves,           // supported_groups (0x000a)
    ExtensionType::ECPointFormats,           // ec_point_formats (0x000b)
    ExtensionType::SessionTicket,            // session_ticket (0x0023)
    ExtensionType::ALProtocolNegotiation,    // application_layer_protocol_negotiation (0x0010)
    ExtensionType::StatusRequest,            // status_request (0x0005)
    ExtensionType::Unknown(0x0022),          // delegated_credentials
    ExtensionType::KeyShare,                 // key_share (0x0033)
    ExtensionType::SupportedVersions,        // supported_versions (0x002b)
    ExtensionType::SignatureAlgorithms,      // signature_algorithms (0x000d)
    ExtensionType::PSKKeyExchangeModes,      // psk_key_exchange_modes (0x002d)
    ExtensionType::Unknown(0x001c),          // record_size_limit
    ExtensionType::Padding,                  // padding (0x0015)
];

/// Named groups advertised by Firefox 128.
static FIREFOX_128_NAMED_GROUPS: &[NamedGroup] = &[
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
    NamedGroup::secp521r1,
    NamedGroup::FFDHE2048,
    NamedGroup::FFDHE3072,
];

/// Signature schemes advertised by Firefox 128.
static FIREFOX_128_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PKCS1_SHA1,
];

/// TLS fingerprint profile for Firefox 128.
///
/// Matches the ClientHello produced by Firefox 128 (NSS). Firefox does not use
/// GREASE and does not shuffle extensions.
pub static FIREFOX_128: Fingerprint = Fingerprint {
    name: "firefox-128",
    cipher_suites: FIREFOX_128_CIPHER_SUITES,
    extensions: FIREFOX_128_EXTENSIONS,
    named_groups: FIREFOX_128_NAMED_GROUPS,
    signature_schemes: FIREFOX_128_SIGNATURE_SCHEMES,
    grease: false,
    shuffle_extensions: false,
};
