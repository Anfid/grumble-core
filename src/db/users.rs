use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind as DieselDatabaseErrorKind, Error as DieselError};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{GetError, InsertError};
use crate::schema::users;

#[derive(Queryable)]
pub struct User {
    pub id: Uuid,
    pub login: String,
    pub nickname: Option<String>,
    pub phash: String,
    pub created_at: OffsetDateTime,
    pub last_online: Option<OffsetDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'l, 'n, 'p> {
    pub login: &'l str,
    pub nickname: Option<&'n str>,
    pub phash: &'p str,
}

pub async fn insert<'conn, 'l, 'n, 'p>(
    conn: &'conn mut AsyncPgConnection,
    user: NewUser<'l, 'n, 'p>,
) -> Result<(), InsertError> {
    diesel::insert_into(users::table)
        .values(user)
        .execute(conn)
        .await
        .map(drop)
        .map_err(|e| match e {
            DieselError::DatabaseError(DieselDatabaseErrorKind::UniqueViolation, _) => {
                InsertError::UniqueViolation(e)
            }
            _ => InsertError::Other(e),
        })
}

pub async fn get_creds<'conn, 'l>(
    conn: &'conn mut AsyncPgConnection,
    login: &'l str,
) -> Result<Option<(Uuid, String)>, GetError> {
    match users::table
        .filter(users::columns::login.eq(&login))
        .select((users::columns::id, users::columns::phash))
        .first(conn)
        .await
    {
        Ok(val) => Ok(Some(val)),
        Err(DieselError::NotFound) => Ok(None),
        Err(e) => Err(GetError::Other(e)),
    }
}
