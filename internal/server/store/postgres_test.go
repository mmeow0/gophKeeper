package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

func TestPostgresAccountAndSessions(t *testing.T) {
	repository, mock, closeDB := newMockPostgres(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	user := User{ID: "u", Username: "alice", AuthSalt: []byte("1234567890123456"), KDF: protocol.KDFParameters{Time: 1, Memory: 8192, Parallelism: 1, KeyLength: 32}, AuthVerifier: []byte("verify"), WrappedVaultKey: []byte("wrapped"), WrapNonce: []byte("nonce"), CreatedAt: now}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO users").WithArgs(
		user.ID, user.Username, user.AuthSalt, user.KDF.Time, user.KDF.Memory, user.KDF.Parallelism,
		user.KDF.KeyLength, user.AuthVerifier, user.WrappedVaultKey, user.WrapNonce, user.CreatedAt,
	).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO vaults").WithArgs("u").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := repository.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	mock.ExpectQuery("SELECT id, username, auth_salt").WithArgs("alice").WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "auth_salt", "kdf_time", "kdf_memory", "kdf_parallelism", "kdf_key_length", "auth_verifier", "wrapped_vault_key", "wrap_nonce", "created_at"}).
			AddRow("u", "alice", user.AuthSalt, 1, 8192, 1, 32, user.AuthVerifier, user.WrappedVaultKey, user.WrapNonce, now),
	)
	if got, err := repository.UserByUsername(ctx, "alice"); err != nil || got.ID != "u" {
		t.Fatalf("UserByUsername() = %#v, %v", got, err)
	}

	session := Session{ID: "s", UserID: "u", AccessTokenHash: []byte("a"), RefreshTokenHash: []byte("r"), AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour), DeviceName: "mac", CreatedAt: now}
	mock.ExpectExec("INSERT INTO sessions").WithArgs(session.ID, session.UserID, session.AccessTokenHash, session.RefreshTokenHash, session.AccessExpiresAt, session.RefreshExpiresAt, session.DeviceName, session.CreatedAt).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := repository.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	sessionRows := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"id", "user_id", "access_token_hash", "refresh_token_hash", "access_expires_at", "refresh_expires_at", "device_name", "revoked_at", "created_at"}).
			AddRow(session.ID, session.UserID, session.AccessTokenHash, session.RefreshTokenHash, session.AccessExpiresAt, session.RefreshExpiresAt, session.DeviceName, nil, session.CreatedAt)
	}
	mock.ExpectQuery("FROM sessions WHERE access_token_hash").WithArgs([]byte("a")).WillReturnRows(sessionRows())
	if got, err := repository.SessionByAccessHash(ctx, []byte("a")); err != nil || got.ID != "s" {
		t.Fatalf("SessionByAccessHash() = %#v, %v", got, err)
	}
	mock.ExpectQuery("FROM sessions WHERE refresh_token_hash").WithArgs([]byte("r")).WillReturnRows(sessionRows())
	if got, err := repository.SessionByRefreshHash(ctx, []byte("r")); err != nil || got.ID != "s" {
		t.Fatalf("SessionByRefreshHash() = %#v, %v", got, err)
	}
	mock.ExpectExec("UPDATE sessions SET revoked_at").WithArgs("s", now).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.RevokeSession(ctx, "s", now); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestPostgresItemsAndSync(t *testing.T) {
	repository, mock, closeDB := newMockPostgres(t)
	defer closeDB()
	ctx := context.Background()
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	incoming := protocol.EncryptedItem{ID: "item", CryptoVersion: 1, Nonce: make([]byte, 24), Ciphertext: []byte("ciphertext")}

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE vaults SET current_revision").WithArgs("u").WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(1))
	mock.ExpectQuery("SELECT item_version FROM items").WithArgs("u", "item").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO items").WithArgs("u", "item", int64(1), int64(1), 1, incoming.Nonce, incoming.Ciphertext, now).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	created, err := repository.PutItem(ctx, "u", "item", 0, incoming, now)
	if err != nil || created.Version != 1 || created.Revision != 1 {
		t.Fatalf("PutItem() = %#v, %v", created, err)
	}

	mock.ExpectQuery("SELECT item_id, item_version").WithArgs("u", "item").WillReturnRows(
		sqlmock.NewRows([]string{"item_id", "item_version", "revision", "crypto_version", "nonce", "ciphertext", "deleted", "updated_at"}).
			AddRow("item", 1, 1, 1, incoming.Nonce, incoming.Ciphertext, false, now),
	)
	if got, err := repository.GetItem(ctx, "u", "item"); err != nil || got.Version != 1 {
		t.Fatalf("GetItem() = %#v, %v", got, err)
	}

	mock.ExpectQuery("SELECT current_revision FROM vaults").WithArgs("u").WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(1))
	mock.ExpectQuery("FROM items WHERE user_id").WithArgs("u", int64(0), 100).WillReturnRows(
		sqlmock.NewRows([]string{"item_id", "item_version", "revision", "crypto_version", "nonce", "ciphertext", "deleted", "updated_at"}).
			AddRow("item", 1, 1, 1, incoming.Nonce, incoming.Ciphertext, false, now),
	)
	if got, err := repository.Sync(ctx, "u", 0, 100); err != nil || len(got.Items) != 1 {
		t.Fatalf("Sync() = %#v, %v", got, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE vaults SET current_revision").WithArgs("u").WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(2))
	mock.ExpectExec("UPDATE items SET item_version").WithArgs("u", "item", int64(1), int64(2), now).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	deleted, err := repository.DeleteItem(ctx, "u", "item", 1, now)
	if err != nil || !deleted.Deleted || deleted.Revision != 2 {
		t.Fatalf("DeleteItem() = %#v, %v", deleted, err)
	}
	assertExpectations(t, mock)
}

func TestPostgresNotFoundAndConflict(t *testing.T) {
	repository, mock, closeDB := newMockPostgres(t)
	defer closeDB()
	ctx := context.Background()
	mock.ExpectQuery("SELECT id, username, auth_salt").WithArgs("none").WillReturnError(sql.ErrNoRows)
	if _, err := repository.UserByUsername(ctx, "none"); err != ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE vaults SET current_revision").WithArgs("u").WillReturnRows(sqlmock.NewRows([]string{"current_revision"}).AddRow(1))
	mock.ExpectQuery("SELECT item_version FROM items").WithArgs("u", "item").WillReturnRows(sqlmock.NewRows([]string{"item_version"}).AddRow(2))
	mock.ExpectRollback()
	if _, err := repository.PutItem(ctx, "u", "item", 1, protocol.EncryptedItem{}, time.Now()); err != ErrConflict {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	assertExpectations(t, mock)
}

func newMockPostgres(t *testing.T) (*Postgres, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	return &Postgres{db: db}, mock, func() { _ = db.Close() }
}

func assertExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
