use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use anyhow::{anyhow, Context, Result};
use diesel_async::pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager};
use dotenvy::dotenv;
use josekit::jws::alg::eddsa::{EddsaJwsSigner, EddsaJwsVerifier};
use josekit::jws::EdDSA;
use std::env;

mod api;
mod auth;
mod db;
mod schema;

use auth::PhashSecret;

type DbPool = Pool<diesel_async::AsyncPgConnection>;

struct Setup {
    db_pool: DbPool,
    secret_key: PhashSecret,
    private_key: EddsaJwsSigner,
    public_key: EddsaJwsVerifier,
    bind_addrs: Vec<std::net::SocketAddr>,
    allowed_origins: Vec<String>,
}

impl Setup {
    fn from_env() -> Result<Self> {
        let var = "DATABASE_URL";
        let database_url = env::var(var).with_context(|| format!("Unable to read '{}'", var))?;
        let db_pool = db_connect(database_url.clone());

        let var = "AUTH_PRIVATE_KEY_PATH";
        let private_key_path =
            env::var(var).with_context(|| format!("Unable to read '{}'", var))?;
        let private_key_pem =
            std::fs::read(private_key_path).with_context(|| format!("Problems with '{}'", var))?;
        let private_key = EdDSA
            .signer_from_pem(private_key_pem)
            .with_context(|| format!("Problems with '{}'", var))?;

        let var = "AUTH_PUBLIC_KEY_PATH";
        let public_key_path = env::var(var).with_context(|| format!("Unable to read '{}'", var))?;
        let public_key_pem =
            std::fs::read(public_key_path).with_context(|| format!("Problems with '{}'", var))?;
        let public_key = EdDSA
            .verifier_from_pem(&public_key_pem)
            .with_context(|| format!("Problems with '{}'", var))?;

        let var = "BIND_ADDRESS";
        let bind_address_str =
            env::var(var).with_context(|| format!("Unable to read '{}'", var))?;
        let bind_address = bind_address_str
            .parse()
            .with_context(|| format!("'{}' is invalid", var))?;
        let bind_addrs = vec![bind_address];

        let var = "PHASH_SECRET_KEY";
        let secret_key = match env::var(var) {
            Ok(secret_hex) => PhashSecret(Some(
                hex::decode(secret_hex).with_context(|| format!("'{}' is invalid", var))?,
            )),
            Err(env::VarError::NotPresent) => PhashSecret(None),
            Err(e) => Err(e).with_context(|| format!("Unable to read '{}'", var))?,
        };

        let var = "ALLOWED_ORIGINS";
        let allowed_origins = env::var(var)
            .with_context(|| format!("Unable to read '{}'", var))?
            .split(",")
            .map(str::trim)
            .map(String::from)
            // Verify origins are valid to avoid panics during HttpServer setup
            .map(|uri| match http::Uri::try_from(&uri) {
                Ok(_) if uri == "*" => Err(anyhow!("wildcard is not allowed")),
                Err(e) => Err(e.into()),
                Ok(_) => Ok(uri),
            })
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("'{}' is invalid", var))?;

        Ok(Self {
            db_pool,
            secret_key,
            private_key,
            public_key,
            bind_addrs,
            allowed_origins,
        })
    }
}

fn db_connect(url: String) -> DbPool {
    let config = AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new(url);
    DbPool::builder(config).build().unwrap()
}

#[actix_web::main]
async fn main() -> Result<()> {
    // Try to load dotenv file, ignore error if the file wasn't found
    let _ = dotenv();

    env_logger::init();

    // Set up configuration from environment variables
    let setup = Setup::from_env()?;

    let secret_key = web::Data::new(setup.secret_key);
    let private_key = web::Data::new(setup.private_key);
    let public_key = web::Data::new(setup.public_key);

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .supports_credentials()
            .max_age(3600);

        for origin in &setup.allowed_origins {
            cors = cors.allowed_origin(origin)
        }

        App::new()
            .app_data(setup.db_pool.clone())
            .app_data(secret_key.clone())
            .app_data(private_key.clone())
            .app_data(public_key.clone())
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .service(api::service())
    })
    .bind(setup.bind_addrs.as_slice())?
    .run()
    .await
    .map_err(Into::into)
}
