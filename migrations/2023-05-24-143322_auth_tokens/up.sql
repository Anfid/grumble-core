CREATE TABLE auth_tokens (
    token bytea PRIMARY KEY UNIQUE,
    token_family bytea NOT NULL,
    user_id UUID NOT NULL REFERENCES users,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ
)
