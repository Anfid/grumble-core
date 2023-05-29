use actix_web::{post, web, HttpResponse, Responder, Scope};
use log::error;

use super::try_or_500;
use crate::{auth, db, DbPool, PhashSecret};

pub fn service() -> Scope {
    Scope::new("/users").service(register)
}

#[post("/register")]
async fn register(
    pool: web::Data<DbPool>,
    phash_secret: web::Data<PhashSecret>,
    user: web::Form<auth::UserCredentials>,
) -> impl Responder {
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
