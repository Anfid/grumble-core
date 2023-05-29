use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind as DieselDatabaseErrorKind, Error as DieselError};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use super::{GetError, InsertError, UpdateError};
use crate::schema::auth_tokens::{self, dsl::*};

#[derive(Queryable, Identifiable)]
#[diesel(table_name = auth_tokens)]
pub struct RefreshToken {
    pub id: Vec<u8>,
    pub token_family: Vec<u8>,
    pub user_id: Uuid,
    pub issued_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub redeemed_at: Option<NaiveDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = auth_tokens)]
pub struct NewRefreshToken<'a> {
    pub token: &'a [u8],
    pub token_family: &'a [u8],
    pub user_id: Uuid,
    pub expires_at: NaiveDateTime,
}

pub async fn get<'conn, 't>(
    conn: &'conn mut AsyncPgConnection,
    token_bytes: &'t [u8],
) -> Result<Option<RefreshToken>, GetError> {
    match auth_tokens.find(&token_bytes).first(conn).await {
        Ok(val) => Ok(Some(val)),
        Err(DieselError::NotFound) => Ok(None),
        Err(e) => Err(GetError::Other(e)),
    }
}

pub async fn get_active<'conn, 't>(
    conn: &'conn mut AsyncPgConnection,
    token_bytes: &'t [u8],
) -> Result<Option<RefreshToken>, GetError> {
    let now = Utc::now().naive_utc();
    match auth_tokens
        .find(&token_bytes)
        .filter(issued_at.le(now))
        .filter(expires_at.gt(now))
        .filter(redeemed_at.is_null())
        .first(conn)
        .await
    {
        Ok(val) => Ok(Some(val)),
        Err(DieselError::NotFound) => Ok(None),
        Err(e) => Err(GetError::Other(e)),
    }
}

pub async fn insert<'conn, 't>(
    conn: &'conn mut AsyncPgConnection,
    token_data: NewRefreshToken<'t>,
) -> Result<(), InsertError> {
    diesel::insert_into(auth_tokens::table)
        .values(token_data)
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

pub async fn redeem<'conn, 't>(
    conn: &'conn mut AsyncPgConnection,
    token_data: &'t [u8],
) -> Result<(), UpdateError> {
    let now = Utc::now().naive_utc();
    diesel::update(auth_tokens.find(token_data))
        .set(redeemed_at.eq(now))
        .execute(conn)
        .await
        .map(drop)
        .map_err(|e| match e {
            DieselError::NotFound => UpdateError::NotFound(e),
            _ => UpdateError::Other(e),
        })
}
