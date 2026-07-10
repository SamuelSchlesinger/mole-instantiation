//! The `Mole` HTTP authentication scheme (draft-jms-mole-http-transport).
//!
//! * A challenge is sent as `WWW-Authenticate: Mole challenge="<b64url>",
//!   realm="<realm>"`. A server offering a choice sends multiple `Mole`
//!   challenges; a recipient ignores challenges whose type it does not
//!   recognize.
//! * A Client answers in the `Authorization` header: `Mole
//!   credential-request="<b64url>"` for Redeem & Issue, `Mole
//!   presentation="<b64url>"` for Presentation.
//! * The Moderator returns credential material in the `Mole-Credential`
//!   response header: `response="<b64url>"` for issuance, `update="<b64url>"`
//!   after a presentation.
//!
//! All values are base64url without padding (RFC 4648).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use thiserror::Error;

/// The HTTP authentication scheme name.
pub const SCHEME: &str = "Mole";
/// The credential-material response header name.
pub const MOLE_CREDENTIAL: &str = "mole-credential";
/// Media type of grant exchange requests.
pub const ENDORSEMENT_REQUEST_MEDIA_TYPE: &str = "application/mole-endorsement-request";
/// Media type of grant exchange responses.
pub const ENDORSEMENT_RESPONSE_MEDIA_TYPE: &str = "application/mole-endorsement-response";

/// Base64url encode without padding.
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64url decode without padding.
pub fn b64_decode(value: &str) -> Result<Vec<u8>, HeaderError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HeaderError::InvalidBase64)
}

/// An error parsing a `Mole` header.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderError {
    /// The header did not use the `Mole` scheme.
    #[error("not a Mole header")]
    NotMole,
    /// The header used the scheme but its parameters were malformed.
    #[error("malformed Mole header parameters")]
    MalformedParams,
    /// A parameter value was not valid unpadded base64url.
    #[error("invalid base64url value")]
    InvalidBase64,
}

/// One `Mole` challenge as carried in a `WWW-Authenticate` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoleChallenge {
    /// The decoded challenge structure bytes.
    pub challenge: Vec<u8>,
    /// The realm parameter, if present ("anchor" or "moderator").
    pub realm: Option<String>,
}

impl MoleChallenge {
    /// Format as a `WWW-Authenticate` header value.
    pub fn to_header_value(&self) -> String {
        match &self.realm {
            Some(realm) => format!(
                "{SCHEME} challenge=\"{}\", realm=\"{realm}\"",
                b64_encode(&self.challenge)
            ),
            None => format!("{SCHEME} challenge=\"{}\"", b64_encode(&self.challenge)),
        }
    }
}

/// The Client's `Authorization` header content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleAuthorization {
    /// Redeem & Issue: a `CredentialRequest`.
    CredentialRequest(Vec<u8>),
    /// Presentation: a `CredentialPresentation`.
    Presentation(Vec<u8>),
}

impl MoleAuthorization {
    /// Format as an `Authorization` header value.
    pub fn to_header_value(&self) -> String {
        match self {
            MoleAuthorization::CredentialRequest(bytes) => {
                format!("{SCHEME} credential-request=\"{}\"", b64_encode(bytes))
            }
            MoleAuthorization::Presentation(bytes) => {
                format!("{SCHEME} presentation=\"{}\"", b64_encode(bytes))
            }
        }
    }

    /// Parse an `Authorization` header value.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let params = parse_scheme_params(value)?;
        if let Some(v) = get_param(&params, "credential-request") {
            return Ok(MoleAuthorization::CredentialRequest(b64_decode(v)?));
        }
        if let Some(v) = get_param(&params, "presentation") {
            return Ok(MoleAuthorization::Presentation(b64_decode(v)?));
        }
        Err(HeaderError::MalformedParams)
    }
}

/// The Moderator's `Mole-Credential` header content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoleCredential {
    /// Issuance: a `CredentialResponse`.
    Response(Vec<u8>),
    /// After a presentation: an `OptionalCredentialUpdate`.
    Update(Vec<u8>),
}

impl MoleCredential {
    /// Format as a `Mole-Credential` header value.
    pub fn to_header_value(&self) -> String {
        match self {
            MoleCredential::Response(bytes) => format!("response=\"{}\"", b64_encode(bytes)),
            MoleCredential::Update(bytes) => format!("update=\"{}\"", b64_encode(bytes)),
        }
    }

    /// Parse a `Mole-Credential` header value.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let params = parse_params(value).ok_or(HeaderError::MalformedParams)?;
        if let Some(v) = get_param(&params, "response") {
            return Ok(MoleCredential::Response(b64_decode(v)?));
        }
        if let Some(v) = get_param(&params, "update") {
            return Ok(MoleCredential::Update(b64_decode(v)?));
        }
        Err(HeaderError::MalformedParams)
    }
}

/// Parse every `Mole` challenge from a list of `WWW-Authenticate` header
/// values. Challenges under other schemes are skipped, as are `Mole`
/// challenges whose parameters are malformed (a recipient ignores what it
/// does not recognize rather than failing the response).
pub fn parse_challenges(header_values: &[&str]) -> Vec<MoleChallenge> {
    let mut out = Vec::new();
    for value in header_values {
        // A header value may carry several comma-separated challenges. Rather
        // than a full RFC 9110 credentials parser, split on occurrences of the
        // scheme token at the start or after a comma: parameters never contain
        // the bare token `Mole ` because their values are quoted base64url.
        for segment in split_challenges(value) {
            let Ok(params) = parse_scheme_params(&segment) else {
                continue;
            };
            let Some(challenge_b64) = get_param(&params, "challenge") else {
                continue;
            };
            let Ok(challenge) = b64_decode(challenge_b64) else {
                continue;
            };
            out.push(MoleChallenge {
                challenge,
                realm: get_param(&params, "realm").map(str::to_string),
            });
        }
    }
    out
}

/// Split a `WWW-Authenticate` value into per-challenge segments on `Mole`
/// scheme tokens.
fn split_challenges(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut rest = value.trim();
    while let Some(start) = find_scheme_token(rest) {
        let after = &rest[start..];
        let next = find_scheme_token(&after[SCHEME.len()..])
            .map(|offset| start + SCHEME.len() + offset)
            .unwrap_or(rest.len());
        segments.push(rest[start..next].trim_end_matches([',', ' ']).to_string());
        rest = &rest[next..];
        if segments.len() > 64 {
            break; // defensive bound
        }
    }
    segments
}

/// Find the byte offset of a `Mole` scheme token that starts a challenge:
/// at the beginning of the string or preceded by a comma (and optional
/// whitespace), and followed by a space.
fn find_scheme_token(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut search_from = 0;
    while let Some(pos) = value[search_from..].find(SCHEME) {
        let idx = search_from + pos;
        let starts_ok = value[..idx].trim_end().is_empty()
            || value[..idx].trim_end().ends_with(',');
        let end = idx + SCHEME.len();
        let ends_ok = bytes.get(end).is_some_and(|b| *b == b' ');
        if starts_ok && ends_ok {
            return Some(idx);
        }
        search_from = end;
    }
    None
}

/// Parse `Mole <params>` into its parameter list.
fn parse_scheme_params(value: &str) -> Result<Vec<(String, String)>, HeaderError> {
    let trimmed = value.trim();
    let rest = trimmed
        .strip_prefix(SCHEME)
        .ok_or(HeaderError::NotMole)?
        .trim_start();
    if rest.is_empty() {
        return Err(HeaderError::MalformedParams);
    }
    parse_params(rest).ok_or(HeaderError::MalformedParams)
}

/// Parse a comma-separated `key="value"` (or `key=value`) auth-param list.
fn parse_params(input: &str) -> Option<Vec<(String, String)>> {
    let mut params = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=')?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        params.push((key.trim().to_ascii_lowercase(), value.to_string()));
    }
    if params.is_empty() {
        None
    } else {
        Some(params)
    }
}

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_round_trips() {
        let challenge = MoleChallenge {
            challenge: vec![1, 2, 3, 255],
            realm: Some("moderator".into()),
        };
        let header = challenge.to_header_value();
        let parsed = parse_challenges(&[header.as_str()]);
        assert_eq!(parsed, vec![challenge]);
    }

    #[test]
    fn multiple_challenges_in_one_header() {
        let a = MoleChallenge {
            challenge: vec![1; 40],
            realm: Some("moderator".into()),
        };
        let b = MoleChallenge {
            challenge: vec![2; 36],
            realm: Some("moderator".into()),
        };
        let combined = format!("{}, {}", a.to_header_value(), b.to_header_value());
        assert_eq!(parse_challenges(&[combined.as_str()]), vec![a, b]);
    }

    #[test]
    fn non_mole_schemes_are_skipped() {
        let parsed = parse_challenges(&[
            "Basic realm=\"x\"",
            "Mole challenge=\"AQID\", realm=\"anchor\"",
        ]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].challenge, vec![1, 2, 3]);
        assert_eq!(parsed[0].realm.as_deref(), Some("anchor"));
    }

    #[test]
    fn authorization_round_trips() {
        for auth in [
            MoleAuthorization::CredentialRequest(vec![9; 64]),
            MoleAuthorization::Presentation(vec![7; 64]),
        ] {
            let header = auth.to_header_value();
            assert_eq!(MoleAuthorization::parse(&header).unwrap(), auth);
        }
    }

    #[test]
    fn credential_header_round_trips() {
        for cred in [
            MoleCredential::Response(vec![1; 32]),
            MoleCredential::Update(vec![2; 32]),
        ] {
            let header = cred.to_header_value();
            assert_eq!(MoleCredential::parse(&header).unwrap(), cred);
        }
    }

    #[test]
    fn malformed_authorization_rejected() {
        assert!(MoleAuthorization::parse("Bearer abc").is_err());
        assert!(MoleAuthorization::parse("Mole").is_err());
        assert!(MoleAuthorization::parse("Mole other=\"AQID\"").is_err());
        assert!(MoleAuthorization::parse("Mole presentation=\"!!!\"").is_err());
    }
}
