use actix_web::cookie::{self, Cookie};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use argon2::PasswordVerifier;
use josekit::jws::alg::eddsa::{EddsaJwsSigner, EddsaJwsVerifier};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{auth, db, DbPool, PhashSecret};

pub fn service() -> Scope {
    Scope::new("/v1")
        .service(register)
        .service(login)
        .service(token)
        .service(revoke)
        .service(test_logged_in)
}

#[derive(Debug, Deserialize)]
struct RegisterParams {
    pub login: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    login: String,
    password: String,
    /// Checkmark implies cookies concent, set refresh token as a persistent cookie
    remember_me: bool,
}

#[derive(Debug, Serialize)]
struct LoginResponse<'j, 't> {
    jwt: &'j str,
    token_type: &'t str,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct AuthorizationErrorResponse {
    reason: AuthorizationErrorReason,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorizationErrorReason {
    TokenMissing,
    InvalidTokenFormat,
    NotYetActive,
    Expired,
    Reused,
}

#[post("/register")]
async fn register(
    req: HttpRequest,
    phash_secret: web::Data<PhashSecret>,
    user: web::Form<RegisterParams>,
) -> impl Responder {
    let pool: &DbPool = req.app_data().unwrap();
    let mut conn = try_or_500!(pool.get().await, "Unable to get database connection");
    let argon2 = auth::argon2_context(&phash_secret);
    let phash = auth::password_to_phash_string(&argon2, user.password.as_bytes());

    let new_user = db::users::NewUser {
        login: &user.login,
        nickname: None,
        phash: phash.as_str(),
    };
    match db::users::insert(&mut conn, new_user).await {
        Ok(()) => HttpResponse::Created().finish(),
        // Entry already exists
        Err(db::InsertError::UniqueViolation(_)) => HttpResponse::Conflict().finish(),
        // Unexpected error,
        Err(db::InsertError::Other(e)) => {
            error!("User registration failed: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/login")]
async fn login(
    req: HttpRequest,
    phash_secret: web::Data<auth::PhashSecret>,
    encoding_key: web::Data<EddsaJwsSigner>,
    params: web::Form<LoginRequest>,
) -> impl Responder {
    let pool: &DbPool = req.app_data().unwrap();
    let mut conn = try_or_500!(pool.get().await, "Unable to get database connection");

    // Get user credential info from the database. Returns 404 if user credential info wasn't found and 500 in case of
    // other errors.
    let (uuid, stored_phash) = if let Some(creds) = try_or_500!(
        db::users::get_creds(&mut conn, &params.login).await,
        "Unable to fetch user credential info"
    ) {
        creds
    } else {
        return HttpResponse::NotFound().json(ErrorMessage {
            message: format!("User {} doesn't exist", &params.login),
        });
    };

    let parsed_hash = try_or_500!(
        password_hash::PasswordHash::new(stored_phash.as_str()),
        "Unable to parse password hash string"
    );
    let auth_result = auth::argon2_context(&phash_secret)
        .verify_password(params.password.as_bytes(), &parsed_hash);

    if auth_result.is_ok() {
        let jwt = try_or_500!(
            auth::Claims::new(uuid, &OffsetDateTime::now_utc()).encode_sign(encoding_key.as_ref()),
            "Unable to encode JWT"
        );

        let new_refresh_token = auth::new_refresh_token();
        match db::refresh_tokens::insert(
            &mut conn,
            db::refresh_tokens::NewRefreshToken {
                token: &new_refresh_token,
                token_family: &new_refresh_token,
                user_id: uuid,
                expires_at: OffsetDateTime::now_utc() + auth::REFRESH_TOKEN_LIFETIME,
            },
        )
        .await
        {
            Ok(()) => {}
            Err(db::InsertError::UniqueViolation(_)) => {
                error!("Unable to generate a unique refresh token");
                return HttpResponse::InternalServerError().finish();
            }
            Err(e @ db::InsertError::Other(_)) => {
                error!("Unable to save new refresh token: {e}");
                return HttpResponse::InternalServerError().finish();
            }
        };

        let new_refresh_token_hex = hex::encode(&new_refresh_token);
        if params.remember_me {
            let cookie = Cookie::build("refresh_token", new_refresh_token_hex)
                .secure(true)
                .http_only(true)
                .same_site(cookie::SameSite::Strict)
                .max_age(auth::REFRESH_TOKEN_LIFETIME.into())
                .finish();
            HttpResponse::Ok().cookie(cookie).json(LoginResponse {
                jwt: &jwt,
                token_type: "Bearer",
                expires_in: auth::JWT_LIFETIME.whole_seconds() as u64,
            })
        } else {
            let cookie = Cookie::build("refresh_token", new_refresh_token_hex)
                .secure(true)
                .http_only(true)
                .same_site(cookie::SameSite::Strict)
                .expires(cookie::Expiration::Session)
                .max_age(
                    auth::REFRESH_TOKEN_LIFETIME
                        .try_into()
                        .expect("Refresh token lifetime too big"),
                )
                .finish();
            HttpResponse::Ok().cookie(cookie).json(LoginResponse {
                jwt: &jwt,
                token_type: "Bearer",
                expires_in: auth::JWT_LIFETIME.whole_seconds() as u64,
            })
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[post("/token")]
async fn token(req: HttpRequest, encoding_key: web::Data<EddsaJwsSigner>) -> impl Responder {
    let pool: &DbPool = req.app_data().unwrap();
    let Some(refresh_cookie) = req.cookie("refresh_token") else {
        return HttpResponse::Unauthorized().json(AuthorizationErrorResponse { reason: AuthorizationErrorReason::TokenMissing });
    };
    let Ok(refresh_token): Result<Vec<u8>, _> = hex::decode(refresh_cookie.value()) else {
        return HttpResponse::Unauthorized().json(AuthorizationErrorResponse { reason: AuthorizationErrorReason::InvalidTokenFormat });
    };

    let mut conn = match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Unable to get database connection: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    match db::refresh_tokens::get(&mut conn, refresh_token.as_ref()).await {
        Ok(Some(token_data)) => {
            let now = OffsetDateTime::now_utc();

            // Check token issue time
            if now < token_data.issued_at {
                warn!("Attempt to use refresh token that was issued in the future");
                return HttpResponse::Unauthorized().json(AuthorizationErrorResponse {
                    reason: AuthorizationErrorReason::NotYetActive,
                });
            }

            // Check token expiry
            if now > token_data.expires_at {
                return HttpResponse::Unauthorized().json(AuthorizationErrorResponse {
                    reason: AuthorizationErrorReason::Expired,
                });
            }

            // Check if token was redeemed. If it was, it's very likely that it was leaked. In that case entire token
            // family has to be invalidated.
            if token_data.redeemed_at.is_some() {
                try_or_500!(
                    db::refresh_tokens::redeem_family(&mut conn, &token_data.token_family, &now)
                        .await,
                    "Unable to invalidate token family on token reuse"
                );

                return HttpResponse::Unauthorized().json(AuthorizationErrorResponse {
                    reason: AuthorizationErrorReason::Reused,
                });
            }

            try_or_500!(
                db::refresh_tokens::redeem(&mut conn, token_data.id.as_ref(), &now).await,
                "Unable to mark token as redeemed"
            );

            let new_refresh_token = auth::new_refresh_token();
            match db::refresh_tokens::insert(
                &mut conn,
                db::refresh_tokens::NewRefreshToken {
                    token: &new_refresh_token,
                    token_family: &token_data.token_family,
                    user_id: token_data.user_id,
                    expires_at: now + auth::REFRESH_TOKEN_LIFETIME,
                },
            )
            .await
            {
                Ok(()) => {}
                Err(db::InsertError::UniqueViolation(_)) => {
                    error!("Unable to generate a unique refresh token");
                    return HttpResponse::InternalServerError().finish();
                }
                Err(e @ db::InsertError::Other(_)) => {
                    error!("Unable to save new refresh token: {e}");
                    return HttpResponse::InternalServerError().finish();
                }
            };

            let jwt = try_or_500!(
                auth::Claims::new(token_data.user_id, &now).encode_sign(encoding_key.as_ref()),
                "Unable to encode JWT"
            );

            HttpResponse::Ok().json(LoginResponse {
                jwt: &jwt,
                token_type: "Bearer",
                expires_in: auth::JWT_LIFETIME.whole_seconds() as u64,
            })
        }
        // Active token not found
        Ok(None) => HttpResponse::Unauthorized().finish(),
        Err(_do_not_leak_error) => {
            error!("Unable to query refresh token");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/revoke")]
async fn revoke(req: HttpRequest) -> impl Responder {
    let pool: &DbPool = req.app_data().unwrap();
    let Some(refresh_cookie) = req.cookie("refresh_token") else {
        return HttpResponse::Unauthorized().json(AuthorizationErrorResponse { reason: AuthorizationErrorReason::TokenMissing });
    };
    let Ok(refresh_token): Result<Vec<u8>, _> = hex::decode(refresh_cookie.value()) else {
        return HttpResponse::Unauthorized().json(AuthorizationErrorResponse { reason: AuthorizationErrorReason::InvalidTokenFormat });
    };

    let mut conn = match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Unable to get database connection: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    match db::refresh_tokens::get(&mut conn, refresh_token.as_ref()).await {
        Ok(Some(token_data)) => {
            let now = OffsetDateTime::now_utc();
            try_or_500!(
                db::refresh_tokens::redeem_family(&mut conn, &token_data.token_family, &now).await,
                "Unable to revoke token family on request"
            );
            HttpResponse::Ok().finish()
        }
        // Active token not found
        Ok(None) => HttpResponse::Unauthorized().finish(),
        Err(_do_not_leak_error) => {
            error!("Unable to query refresh token");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/test_logged_in")]
async fn test_logged_in(
    auth: BearerAuth,
    decoding_key: web::Data<EddsaJwsVerifier>,
) -> impl Responder {
    let auth_result = auth::Claims::decode(decoding_key.as_ref(), auth.token());
    let now = OffsetDateTime::now_utc();
    match auth_result {
        Ok(claims) => match claims.verify_claims(now) {
            Ok(authorized) => {
                HttpResponse::Ok().body(format!("Logged in as user {}", authorized.user))
            }
            Err(e) => HttpResponse::Ok().body(format!("Not logged in, verification failed: {e}")),
        },
        Err(e) => HttpResponse::Ok().body(format!("Not logged in, verification failed: {e}")),
    }
}

#[derive(Serialize)]
pub struct ErrorMessage<M: AsRef<str>> {
    message: M,
}

macro_rules! try_or_500 {
    ($fallible:expr, $message:expr) => {
        match $fallible {
            Ok(result) => result,
            Err(cause) => {
                error!("{}: {}", $message, cause);
                return actix_web::HttpResponse::InternalServerError().finish();
            }
        }
    };
}
pub(crate) use try_or_500;
