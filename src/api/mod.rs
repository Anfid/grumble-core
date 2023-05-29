use actix_web::Scope;
use serde::Serialize;

mod auth;
mod users;

pub fn service() -> Scope {
    Scope::new("/api/v1")
        .service(auth::service())
        .service(users::service())
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
