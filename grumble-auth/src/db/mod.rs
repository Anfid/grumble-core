use diesel::result::Error as DieselError;
use thiserror::Error;

pub mod refresh_tokens;
pub mod users;

#[derive(Debug, Error)]
pub enum InsertError {
    #[error("entry already exists in the database")]
    UniqueViolation(#[source] DieselError),
    #[error("unable to insert new entry into the database")]
    Other(#[source] DieselError),
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("entry doesn't exists in the database")]
    NotFound(#[source] DieselError),
    #[error("unable to update existing entry in the database")]
    Other(#[source] DieselError),
}

#[derive(Debug, Error)]
pub enum GetError {
    #[error("unable to query entry from the database")]
    Other(#[source] DieselError),
}
