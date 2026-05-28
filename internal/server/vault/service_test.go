package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
)

func TestServiceStoresSyncsAndDeletesItems(t *testing.T) {
	ctx := context.Background()
	repository := store.NewMemory()
	if err := repository.CreateUser(ctx, store.User{ID: "user", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(repository)

	created, err := service.Put(ctx, "user", "item", validPut(0, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 || created.Revision != 1 || created.Deleted {
		t.Fatalf("created item = %#v", created)
	}
	if got, err := service.Get(ctx, "user", "item"); err != nil || got.ID != "item" {
		t.Fatalf("Get() = %#v, %v", got, err)
	}
	if _, err := service.Put(ctx, "user", "item", validPut(0, "stale")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale Put() error = %v", err)
	}

	updated, err := service.Put(ctx, "user", "item", validPut(created.Version, "second"))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := service.Sync(ctx, "user", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Items) != 1 || changes.CurrentRevision != updated.Revision {
		t.Fatalf("Sync() = %#v", changes)
	}

	deleted, err := service.Delete(ctx, "user", "item", protocol.DeleteItemRequest{BaseVersion: updated.Version})
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.Version != updated.Version+1 {
		t.Fatalf("deleted item = %#v", deleted)
	}
	if _, err := service.Get(ctx, "user", "item"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v", err)
	}
}

func TestServiceRejectsInvalidRequests(t *testing.T) {
	service := NewService(store.NewMemory())
	if _, err := service.Put(context.Background(), "user", "", protocol.PutItemRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Put() error = %v", err)
	}
	if _, err := service.Delete(context.Background(), "user", "item", protocol.DeleteItemRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Delete() error = %v", err)
	}
	if _, err := service.Sync(context.Background(), "user", -1, 100); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Sync() error = %v", err)
	}
}

func validPut(baseVersion int64, text string) protocol.PutItemRequest {
	return protocol.PutItemRequest{
		BaseVersion:   baseVersion,
		CryptoVersion: 1,
		Nonce:         make([]byte, 24),
		Ciphertext:    []byte(text),
	}
}
