use actix_web::{get, post, web, HttpResponse, Responder, Scope};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use argon2::PasswordVerifier;
use chrono::Utc;
use log::error;
use serde::{Deserialize, Serialize};

use super::{try_or_500, ErrorMessage};
use crate::{auth, db, DbPool};

pub fn service() -> Scope {
    Scope::new("/auth")
        .service(login)
        .service(token)
        .service(revoke)
        .service(test_logged_in)
}

#[derive(Debug, Serialize)]
struct LoginResponse<'j, 't, 'r> {
    jwt: &'j str,
    token_type: &'t str,
    expires_in: u64,
    refresh_token: &'r str,
}

#[post("/login")]
async fn login(
    pool: web::Data<DbPool>,
    phash_secret: web::Data<auth::PhashSecret>,
    encoding_key: web::Data<jsonwebtoken::EncodingKey>,
    user: web::Form<auth::UserCredentials>,
) -> impl Responder {
    let mut conn = try_or_500!(pool.get().await, "Unable to get database connection");

    // Get user credential info from the database. Returns 404 if user credential info wasn't found and 500 in case of
    // other errors.
    let (uuid, stored_phash) = if let Some(creds) = try_or_500!(
        db::users::get_creds(&mut conn, &user.login).await,
        "Unable to fetch user credential info"
    ) {
        creds
    } else {
        return HttpResponse::NotFound().json(ErrorMessage {
            message: format!("User {} doesn't exist", &user.login),
        });
    };

    let parsed_hash = try_or_500!(
        password_hash::PasswordHash::new(stored_phash.as_str()),
        "Unable to parse password hash string"
    );
    let auth_result =
        auth::argon2_context(&phash_secret).verify_password(user.password.as_bytes(), &parsed_hash);

    if auth_result.is_ok() {
        let jwt = try_or_500!(
            auth::JwtData::new(uuid).encode(&*encoding_key),
            "Unable to encode JWT"
        );

        let refresh_token = auth::new_refresh_token();
        match db::refresh_tokens::insert(
            &mut conn,
            db::refresh_tokens::NewRefreshToken {
                token: &refresh_token,
                token_family: &refresh_token,
                user_id: uuid,
                expires_at: Utc::now().naive_utc()
                    + chrono::Duration::from_std(auth::REFRESH_TOKEN_LIFETIME).unwrap(),
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

        HttpResponse::Ok().json(LoginResponse {
            jwt: &jwt,
            token_type: "Bearer",
            expires_in: auth::JWT_LIFETIME.as_secs(),
            refresh_token: &hex::encode(refresh_token),
        })
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[derive(Deserialize)]
struct TokenParams {
    #[serde(with = "hex::serde")]
    refresh_token: Vec<u8>,
}

#[post("/token")]
async fn token(
    pool: web::Data<DbPool>,
    encoding_key: web::Data<jsonwebtoken::EncodingKey>,
    token_params: web::Form<TokenParams>,
) -> impl Responder {
    let mut conn = match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Unable to get database connection: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    // TODO: Revoke token family on reuse
    match db::refresh_tokens::get_active(&mut conn, token_params.refresh_token.as_ref()).await {
        Ok(Some(token_data)) => {
            try_or_500!(
                db::refresh_tokens::redeem(&mut conn, token_data.id.as_ref()).await,
                "Unable to mark token as redeemed"
            );

            let refresh_token = auth::new_refresh_token();
            match db::refresh_tokens::insert(
                &mut conn,
                db::refresh_tokens::NewRefreshToken {
                    token: &refresh_token,
                    token_family: &token_data.token_family,
                    user_id: token_data.user_id,
                    expires_at: Utc::now().naive_utc()
                        + chrono::Duration::from_std(auth::REFRESH_TOKEN_LIFETIME).unwrap(),
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
                auth::JwtData::new(token_data.user_id).encode(&*encoding_key),
                "Unable to encode JWT"
            );

            HttpResponse::Ok().json(LoginResponse {
                jwt: &jwt,
                token_type: "Bearer",
                expires_in: auth::JWT_LIFETIME.as_secs(),
                refresh_token: &hex::encode(refresh_token),
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
async fn revoke() -> impl Responder {
    HttpResponse::NotImplemented().finish()
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
