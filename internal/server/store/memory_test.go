package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

func TestMemoryAccountsSessionsAndItems(t *testing.T) {
	ctx := context.Background()
	repository := NewMemory()
	user := User{
		ID:              "user",
		Username:        "alice",
		AuthSalt:        []byte("salt"),
		AuthVerifier:    []byte("verifier"),
		WrappedVaultKey: []byte("wrapped"),
		WrapNonce:       []byte("nonce"),
	}
	if err := repository.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateUser(ctx, user); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate CreateUser() error = %v", err)
	}
	gotUser, err := repository.UserByUsername(ctx, "alice")
	if err != nil || gotUser.ID != "user" {
		t.Fatalf("UserByUsername() = %#v, %v", gotUser, err)
	}
	gotUser.AuthSalt[0] = 'x'
	gotUser, err = repository.UserByUsername(ctx, "alice")
	if err != nil || bytes.Equal(gotUser.AuthSalt, []byte("xalt")) {
		t.Fatal("UserByUsername returned mutable user state")
	}

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	session := Session{
		ID:               "session",
		UserID:           "user",
		AccessTokenHash:  []byte("access"),
		RefreshTokenHash: []byte("refresh"),
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:        now,
	}
	if err := repository.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	if got, err := repository.SessionByAccessHash(ctx, []byte("access")); err != nil || got.ID != "session" {
		t.Fatalf("SessionByAccessHash() = %#v, %v", got, err)
	}
	if got, err := repository.SessionByRefreshHash(ctx, []byte("refresh")); err != nil || got.ID != "session" {
		t.Fatalf("SessionByRefreshHash() = %#v, %v", got, err)
	}
	if err := repository.RevokeSession(ctx, "session", now); err != nil {
		t.Fatal(err)
	}
	revoked, err := repository.SessionByAccessHash(ctx, []byte("access"))
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoked session = %#v, %v", revoked, err)
	}

	first := protocol.EncryptedItem{CryptoVersion: 1, Nonce: []byte("nonce-1"), Ciphertext: []byte("cipher-1")}
	created, err := repository.PutItem(ctx, "user", "item", 0, first, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 || created.Revision != 1 {
		t.Fatalf("created item = %#v", created)
	}
	if _, err := repository.PutItem(ctx, "user", "item", 0, first, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale PutItem() error = %v", err)
	}
	second := protocol.EncryptedItem{CryptoVersion: 1, Nonce: []byte("nonce-2"), Ciphertext: []byte("cipher-2")}
	updated, err := repository.PutItem(ctx, "user", "item", created.Version, second, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repository.GetItem(ctx, "user", "item"); err != nil || got.Version != updated.Version {
		t.Fatalf("GetItem() = %#v, %v", got, err)
	}
	changes, err := repository.Sync(ctx, "user", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Items) != 1 || changes.CurrentRevision != updated.Revision {
		t.Fatalf("Sync() = %#v", changes)
	}
	deleted, err := repository.DeleteItem(ctx, "user", "item", updated.Version, now)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.Version != updated.Version+1 {
		t.Fatalf("DeleteItem() = %#v", deleted)
	}
	if _, err := repository.DeleteItem(ctx, "user", "item", deleted.Version, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete tombstone error = %v", err)
	}
}

func TestMemoryMissingEntities(t *testing.T) {
	repository := NewMemory()
	ctx := context.Background()
	if _, err := repository.UserByUsername(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
	if _, err := repository.SessionByAccessHash(ctx, []byte("missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing access session error = %v", err)
	}
	if _, err := repository.SessionByRefreshHash(ctx, []byte("missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing refresh session error = %v", err)
	}
	if err := repository.RevokeSession(ctx, "missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revoke error = %v", err)
	}
	if _, err := repository.GetItem(ctx, "missing", "item"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item error = %v", err)
	}
	if _, err := repository.Sync(ctx, "missing", 0, 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing sync error = %v", err)
	}
}
