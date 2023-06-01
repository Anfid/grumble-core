use actix_web::cookie::{self, Cookie};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use argon2::PasswordVerifier;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{try_or_500, ErrorMessage};
use crate::{auth, db, DbPool};

pub fn service() -> Scope {
    Scope::new("/auth")
        .service(login)
        .service(token)
        .service(revoke)
        .service(test_logged_in)
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

#[post("/login")]
async fn login(
    pool: web::Data<DbPool>,
    phash_secret: web::Data<auth::PhashSecret>,
    encoding_key: web::Data<jsonwebtoken::EncodingKey>,
    params: web::Form<LoginRequest>,
) -> impl Responder {
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
            auth::JwtData::new(uuid, &OffsetDateTime::now_utc()).encode(&*encoding_key),
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
                .expires(cookie::Expiration::Session)
                .max_age(
                    auth::REFRESH_TOKEN_LIFETIME
                        .try_into()
                        .expect("Refresh token lifetime too big"),
                )
                .same_site(cookie::SameSite::Strict)
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

#[post("/token")]
async fn token(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    encoding_key: web::Data<jsonwebtoken::EncodingKey>,
) -> impl Responder {
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
                auth::JwtData::new(token_data.user_id, &now).encode(&*encoding_key),
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
async fn revoke(req: HttpRequest, pool: web::Data<DbPool>) -> impl Responder {
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
    decoding_key: web::Data<jsonwebtoken::DecodingKey>,
) -> impl Responder {
    let auth_result = auth::JwtData::decode(&*decoding_key, auth.token());
    match auth_result {
        Ok(jwt) => HttpResponse::Ok().body(format!("Logged in as user {}", jwt.claims.sub)),
        Err(e) => HttpResponse::Ok().body(format!("Not logged in, verification failed: {}", e)),
    }
}
