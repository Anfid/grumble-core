use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use diesel_async::pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager};
use dotenvy::dotenv;
use josekit::jws::EdDSA;
use std::env;

mod api;
mod auth;
mod db;
mod schema;

use auth::PhashSecret;

type DbPool = Pool<diesel_async::AsyncPgConnection>;

fn db_connect(url: &str) -> DbPool {
    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(
        std::env::var("DATABASE_URL").expect("DATABASE_URL is not set"),
    );
    DbPool::builder(config)
        .build()
        .unwrap_or_else(|e| panic!("Error connecting to the database at '{url}': {e}"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init();

    // TODO: Rework server initialization
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_connection_pool = db_connect(&database_url);

    let secret = PhashSecret(
        env::var("PHASH_SECRET_KEY")
            .ok()
            .map(hex::decode)
            .transpose()
            .expect("PHASH_SECRET_KEY must be a valid hex string"),
    );
    let private_key = EdDSA
        .signer_from_pem(&std::fs::read(env::var("AUTH_PRIVATE_KEY_PATH").unwrap()).unwrap())
        .unwrap();
    let public_key = EdDSA
        .verifier_from_pem(&std::fs::read(env::var("AUTH_PUBLIC_KEY_PATH").unwrap()).unwrap())
        .unwrap();

    let bind_address = env::var("BIND_ADDRESS").expect("BIND_ADDRESS must be set");

    let phash_secret_data = web::Data::new(secret);
    let private_key_data = web::Data::new(private_key);
    let public_key_data = web::Data::new(public_key);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allowed_origin("http://localhost")
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(db_connection_pool.clone()))
            .app_data(phash_secret_data.clone())
            .app_data(private_key_data.clone())
            .app_data(public_key_data.clone())
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .service(api::service())
    })
    .bind(bind_address)?
    .run()
    .await
}
