use argon2::Argon2;
use chrono::Utc;
use password_hash::{PasswordHashString, PasswordHasher, SaltString};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// JWTs are considered expired after this duration. Current value: 10 minutes.
pub const JWT_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Refresh tokens are considered expired after this duration. Current value: 90 days.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// An acceptable margin of error for tokin verification. Current value: 5 minutes.
pub const TOKEN_LIFETIME_LEEWAY: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Deserialize)]
pub(crate) struct UserCredentials {
    pub login: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PhashSecret(pub Option<Vec<u8>>);

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
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Expiration time (as UTC timestamp)
    pub exp: u64,
    /// Audience
    pub aud: String,
    /// Issuer
    pub iss: String,
    /// Subject (whom token refers to)
    pub sub: String,
    /// Optional. Not Before (as UTC timestamp)
    pub nbf: Option<u64>,
    /// Optional. Issued at (as UTC timestamp)
    pub iat: Option<u64>,
}

pub struct JwtData {
    pub header: jsonwebtoken::Header,
    pub claims: Claims,
}

impl JwtData {
    pub fn new(user_id: Uuid) -> Self {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let timestamp = Utc::now().timestamp() as u64;
        let claims = Claims {
            exp: timestamp + JWT_LIFETIME.as_secs(),
            aud: "grumble".to_string(),
            iss: "grumble".to_string(),
            sub: user_id.urn().to_string(),
            nbf: None,
            iat: Some(timestamp),
        };

        Self { header, claims }
    }

    /// Encode JWT and serialize it to string.
    pub fn encode(
        &self,
        key: &jsonwebtoken::EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(&self.header, &self.claims, key)
    }

    /// Parse string, verify signature and decode JWT.
    pub fn decode(
        key: &jsonwebtoken::DecodingKey,
        token: &str,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.required_spec_claims = ["exp", "aud", "iss", "sub"]
            .map(String::from)
            .into_iter()
            .collect();
        validation.leeway = TOKEN_LIFETIME_LEEWAY.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_audience(&["grumble"]);
        validation.set_issuer(&["grumble"]);

        jsonwebtoken::decode(token, key, &validation).map(|data| Self {
            header: data.header,
            claims: data.claims,
        })
    }
}

pub(crate) fn new_refresh_token() -> [u8; 32] {
    let mut token_bytes = [0; 32];
    // Initializing StdRng on each request improves security of generated tokens
    StdRng::from_entropy().fill_bytes(&mut token_bytes);

    token_bytes
}
