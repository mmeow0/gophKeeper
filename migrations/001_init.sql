CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    auth_salt BYTEA NOT NULL,
    kdf_time INTEGER NOT NULL,
    kdf_memory INTEGER NOT NULL,
    kdf_parallelism SMALLINT NOT NULL,
    kdf_key_length INTEGER NOT NULL,
    auth_verifier BYTEA NOT NULL,
    wrapped_vault_key BYTEA NOT NULL,
    wrap_nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    current_revision BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash BYTEA NOT NULL UNIQUE,
    refresh_token_hash BYTEA NOT NULL UNIQUE,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    item_version BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    crypto_version INTEGER NOT NULL,
    nonce BYTEA,
    ciphertext BYTEA,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, item_id)
);

CREATE INDEX IF NOT EXISTS items_sync_idx ON items(user_id, revision);

