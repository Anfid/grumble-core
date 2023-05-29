// @generated automatically by Diesel CLI.

diesel::table! {
    auth_tokens (token) {
        token -> Bytea,
        token_family -> Bytea,
        user_id -> Uuid,
        issued_at -> Timestamp,
        expires_at -> Timestamp,
        redeemed_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        login -> Text,
        nickname -> Nullable<Text>,
        phash -> Text,
        created_at -> Timestamp,
        last_online -> Nullable<Timestamp>,
    }
}

diesel::joinable!(auth_tokens -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    auth_tokens,
    users,
);
