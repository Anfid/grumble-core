use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind as DieselDatabaseErrorKind, Error as DieselError};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{GetError, InsertError, UpdateError};
use crate::schema::auth_tokens::{self, dsl::*};

#[derive(Queryable, Identifiable)]
#[diesel(table_name = auth_tokens)]
pub struct RefreshToken {
    pub id: Vec<u8>,
    pub token_family: Vec<u8>,
    pub user_id: Uuid,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = auth_tokens)]
pub struct NewRefreshToken<'a> {
    pub token: &'a [u8],
    pub token_family: &'a [u8],
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
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
    token_id: &'t [u8],
    now: &OffsetDateTime,
) -> Result<(), UpdateError> {
    diesel::update(auth_tokens.find(token_id))
        .set(redeemed_at.eq(now))
        .execute(conn)
        .await
        .map(drop)
        .map_err(|e| match e {
            DieselError::NotFound => UpdateError::NotFound(e),
            _ => UpdateError::Other(e),
        })
}

pub async fn redeem_family<'conn, 't>(
    conn: &'conn mut AsyncPgConnection,
    family_id: &'t [u8],
    now: &OffsetDateTime,
) -> Result<(), UpdateError> {
    diesel::update(auth_tokens.filter(token_family.eq(family_id)))
        .set(redeemed_at.eq(now))
        .execute(conn)
        .await
        .map(drop)
        .map_err(|e| match e {
            DieselError::NotFound => UpdateError::NotFound(e),
            _ => UpdateError::Other(e),
        })
}
