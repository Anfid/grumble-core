use argon2::Argon2;
use josekit::jws::{JwsHeader, JwsSigner, JwsVerifier};
use josekit::jwt::{self, JwtPayload};
use josekit::JoseError;
use password_hash::{PasswordHashString, PasswordHasher, SaltString};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// JWTs are considered expired after this duration. Current value: 10 minutes.
pub const JWT_LIFETIME: Duration = Duration::minutes(10);
/// Refresh tokens are considered expired after this duration. Current value: 90 days.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(90);

/// An acceptable margin of error for tokin verification. Current value: 5 minutes.
pub const TOKEN_LIFETIME_LEEWAY: Duration = Duration::minutes(5);

/// A secret that can be included for each pasword hash. Passwords hashed using this secret require same secret phrase
/// for verification.
#[derive(Debug, Clone)]
pub(crate) struct PhashSecret(pub Option<Vec<u8>>);

/// Initialize a password hasher context with consistent parameter set.
pub(crate) fn argon2_context<'s>(secret: &'s PhashSecret) -> Argon2<'s> {
    let algorithm = argon2::Algorithm::Argon2id;
    let version = argon2::Version::V0x13;
    let params = argon2::Params::default();

    match &secret.0 {
        Some(secret) => Argon2::new_with_secret(&secret, algorithm, version, params)
            .expect("PHASH_SECRET_KEY too long"),
        None => Argon2::new(algorithm, version, params),
    }
}

/// Hash a password for storing in the database. Adds extra random salt to each password.
pub(crate) fn password_to_phash_string<'s>(
    context: &Argon2<'s>,
    password_bytes: &[u8],
) -> PasswordHashString {
    let psalt = SaltString::generate(&mut StdRng::from_entropy());
    context
        .hash_password(password_bytes, &psalt)
        // Should not fail with given params
        .expect("Unable to hash password")
        .serialize()
}

/// JWT claims
#[derive(Debug)]
pub struct Claims(JwtPayload);

impl Claims {
    /// Create a default set of claims for user [user_id].
    pub fn new(user_id: Uuid, now: &OffsetDateTime) -> Self {
        let mut payload = JwtPayload::new();
        payload.set_expires_at(&(*now + JWT_LIFETIME).into());
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(user_id.urn().to_string());

        Self(payload)
    }

    /// Encode JWT claims and sign them with given private key.
    pub fn encode_sign(self, key: &impl JwsSigner) -> Result<String, JoseError> {
        let mut header = JwsHeader::new();
        header.set_algorithm(key.algorithm().name());

        jwt::encode_with_signer(&self.0, &header, key)
    }

    /// Decode JWT claims and verify signature with given public key.
    pub fn decode(key: &impl JwsVerifier, token: &str) -> Result<Self, JoseError> {
        jwt::decode_with_verifier(token, key).map(|(payload, _)| Self(payload))
    }

    /// Verify JWT claims and get user info
    pub fn verify_claims(
        &self,
        now: OffsetDateTime,
    ) -> Result<AuthorizedUser, ClaimsVerificationError> {
        let subject = self
            .0
            .subject()
            .ok_or(ClaimsVerificationError::ClaimMissing)?;
        let user = Uuid::parse_str(subject).map_err(|_| ClaimsVerificationError::InvalidUserId)?;

        if self.0.issuer() != Some("grumble") {
            return Err(ClaimsVerificationError::UnknownIssuer);
        }

        if self
            .0
            .audience()
            .map(|audience| !audience.contains(&"grumble"))
            .unwrap_or(true)
        {
            return Err(ClaimsVerificationError::AudienceMismatch);
        }

        let expiry = self
            .0
            .expires_at()
            .ok_or(ClaimsVerificationError::ClaimMissing)?;

        if now > expiry + TOKEN_LIFETIME_LEEWAY {
            return Err(ClaimsVerificationError::TokenExpired);
        }

        if self
            .0
            .not_before()
            .is_some_and(|not_before| now < not_before)
        {
            return Err(ClaimsVerificationError::TokenNotYetActive);
        }

        if self.0.issued_at().is_some_and(|issued_at| now < issued_at) {
            return Err(ClaimsVerificationError::TokenNotYetActive);
        }

        Ok(AuthorizedUser { user })
    }
}

/// User with their identity confirmed by verifying provided JWT.
#[derive(Debug)]
pub struct AuthorizedUser {
    pub user: Uuid,
}

/// Error that occured during JWT claims verification
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimsVerificationError {
    /// Required claim is missing
    #[error("required claim missing")]
    ClaimMissing,
    /// User ID could not be parsed
    #[error("invalid user ID")]
    InvalidUserId,
    /// Issuer verification fail
    #[error("unknown issuer")]
    UnknownIssuer,
    /// Audience verification fail
    #[error("audience mismatch")]
    AudienceMismatch,
    /// Token already expired
    #[error("token expired")]
    TokenExpired,
    /// Token is not yet active or was issued in the future
    #[error("token not yet active")]
    TokenNotYetActive,
}

/// Generate random bytes for refresh token
pub fn new_refresh_token() -> [u8; 32] {
    let mut token_bytes = [0; 32];
    // Initializing StdRng on each request improves security of generated tokens
    StdRng::from_entropy().fill_bytes(&mut token_bytes);

    token_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jws::{EdDSA, ES512};
    use std::time::SystemTime;

    const PRIVATE_TEST_KEY: &str = "\
        -----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIHYMMzy4pcknTawU4ILwjZzFZLvdm7BYBFkXaDamf8Ef\n\
        -----END PRIVATE KEY-----";

    const PUBLIC_TEST_KEY: &str = "\
        -----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEAp4tyhXtwJ+zOrCbzENlP6WIEM0xbtFAEwdc9YT1RrtM=\n\
        -----END PUBLIC KEY-----";

    const UNKNOWN_PRIVATE_TEST_KEY: &str = "\
        -----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIPUozvGIp0U6l9fGmZW2sbwGjsq+SILcGlYNR0aQsNvk\n\
        -----END PRIVATE KEY-----";

    const UNKNOWN_PRIVATE_TEST_EC_KEY: &str = "\
        -----BEGIN EC PRIVATE KEY-----\n\
        MIHbAgEBBEFDsxe+ApHz+jStMUDMazU+aotah1kR8DgCvHasJieIh2H/SUIBiv68\n\
        VFwGOhDKnIuvHGP7WnZ5sKUH+/etexwh7KAHBgUrgQQAI6GBiQOBhgAEABWPisJ7\n\
        7bdneki5uxMU7pICuPIFiSB7WCrWKd2niWqjNuvv6D8gmJp5YAsQX9cD8WrUH32i\n\
        JUv0XUJqcqkm3BzZAYXCl+bLadq5Oc7i7OV/mk0P1pjQzWxMjO+i6nJ904lylxYr\n\
        a0apZLttCaGkkXvqkqYsm/831Wy5bfQIx0KMskgc\n\
        -----END EC PRIVATE KEY-----";

    const USER_1: Uuid = Uuid::from_bytes([
        0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8,
    ]);

    fn private_test_key() -> impl JwsSigner {
        EdDSA
            .signer_from_pem(PRIVATE_TEST_KEY.as_bytes())
            .expect("Unable to parse test private key")
    }

    fn public_test_key() -> impl JwsVerifier {
        EdDSA
            .verifier_from_pem(PUBLIC_TEST_KEY.as_bytes())
            .expect("Unable to parse test public key")
    }

    fn unknown_private_test_key() -> impl JwsSigner {
        EdDSA
            .signer_from_pem(UNKNOWN_PRIVATE_TEST_KEY.as_bytes())
            .expect("Unable to parse test private key")
    }

    fn unknown_private_test_ec_key() -> impl JwsSigner {
        ES512
            .signer_from_pem(UNKNOWN_PRIVATE_TEST_EC_KEY.as_bytes())
            .expect("Unable to parse test private key")
    }

    // Returns time with offset for testing purposes.
    fn test_now() -> OffsetDateTime {
        time::PrimitiveDateTime::new(
            time::Date::from_ordinal_date(2023, 42).unwrap(),
            time::Time::from_hms(18, 32, 5).unwrap(),
        )
        .assume_offset(time::UtcOffset::from_hms(2, 0, 0).unwrap())
    }

    pub fn encode_sign(
        claims: &JwtPayload,
        key: &impl JwsSigner,
    ) -> Result<String, josekit::JoseError> {
        let mut header = JwsHeader::new();
        header.set_algorithm(key.algorithm().name());

        jwt::encode_with_signer(&claims, &header, key)
    }

    #[test]
    fn jwt_verify_valid() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        // Valid payload
        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        let user = Claims::decode(&public_test_key(), &jwt)?.verify_claims(now)?;
        assert_eq!(user.user, USER_1);

        Ok(())
    }

    #[test]
    fn jwt_verify_leeway() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        let mut payload = JwtPayload::new();
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        // JWT is expired, but still within allowed leeway
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        Claims::decode(&public_test_key(), &jwt)?.verify_claims(now)?;
        Ok(())
    }

    #[test]
    fn jwt_verify_expired() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        let mut payload = JwtPayload::new();
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        // JWT expired TOKEN_LIFETIME_LEEWAY + 1 second ago
        payload.set_expires_at(&SystemTime::from(
            now - TOKEN_LIFETIME_LEEWAY - Duration::seconds(1),
        ));

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert_eq!(
            Claims::decode(&public_test_key(), &jwt)?
                .verify_claims(now)
                .expect_err("No error on expired token verification"),
            ClaimsVerificationError::TokenExpired
        );

        Ok(())
    }

    #[test]
    fn jwt_verify_audience_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        // Audience of this token is unknown
        payload.set_audience(vec!["unknown"]);

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert_eq!(
            Claims::decode(&public_test_key(), &jwt)?
                .verify_claims(now)
                .expect_err("No error on expired token verification"),
            ClaimsVerificationError::AudienceMismatch
        );

        Ok(())
    }

    #[test]
    fn jwt_verify_unknown_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_subject(USER_1.urn().to_string());

        // Issuer of this token is unknown
        payload.set_issuer("unknown");

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert_eq!(
            Claims::decode(&public_test_key(), &jwt)?
                .verify_claims(now)
                .expect_err("No error on expired token verification"),
            ClaimsVerificationError::UnknownIssuer
        );

        Ok(())
    }

    #[test]
    fn jwt_verify_no_subject() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        // Subject of this token is not specified
        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert_eq!(
            Claims::decode(&public_test_key(), &jwt)?
                .verify_claims(now)
                .expect_err("No error on expired token verification"),
            ClaimsVerificationError::ClaimMissing
        );

        Ok(())
    }

    #[test]
    fn jwt_verify_invalid_subject() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");

        // Subject of this token has invalid format
        payload.set_subject("invalid user ID");

        let jwt = encode_sign(&payload, &private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert_eq!(
            Claims::decode(&public_test_key(), &jwt)?
                .verify_claims(now)
                .expect_err("No error on expired token verification"),
            ClaimsVerificationError::InvalidUserId
        );

        Ok(())
    }

    #[test]
    fn jwt_verify_unknown_signature() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        // Valid payload
        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        // Unknown private key used for signing
        let jwt = encode_sign(&payload, &unknown_private_test_key())
            .expect("Unable to encode and sign a valid jwt");

        assert!(matches!(
            Claims::decode(&public_test_key(), &jwt),
            Err(JoseError::InvalidSignature(_))
        ));

        Ok(())
    }

    #[test]
    fn jwt_verify_unknown_signature_algorithm() -> Result<(), Box<dyn std::error::Error>> {
        let now = test_now();

        // Valid payload
        let mut payload = JwtPayload::new();
        payload.set_expires_at(&SystemTime::from(now + JWT_LIFETIME));
        payload.set_audience(vec!["grumble"]);
        payload.set_issuer("grumble");
        payload.set_subject(USER_1.urn().to_string());

        // Unknown private key used for signing
        let jwt = encode_sign(&payload, &unknown_private_test_ec_key())
            .expect("Unable to encode and sign a valid jwt");

        assert!(matches!(
            Claims::decode(&public_test_key(), &jwt),
            Err(JoseError::InvalidJwsFormat(_))
        ));

        Ok(())
    }
}
