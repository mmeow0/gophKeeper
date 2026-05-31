package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"

	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
)

func TestServiceSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	repository := store.NewMemory()
	service := NewService(repository, []byte("pepper"))
	setup := newTestVaultSetup(t, "alice", "long master password")

	err := service.Register(ctx, protocol.RegisterRequest{
		Username:        " Alice ",
		AuthSalt:        setup.AuthSalt,
		KDF:             setup.KDF,
		AuthKey:         setup.AuthKey,
		WrappedVaultKey: setup.WrappedVaultKey,
		WrapNonce:       setup.WrapNonce,
	})
	if err != nil {
		t.Fatal(err)
	}

	parameters, err := service.LoginParameters(ctx, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parameters.AuthSalt, setup.AuthSalt) {
		t.Fatal("login parameters returned a different salt")
	}

	if _, err := service.Login(ctx, protocol.LoginRequest{Username: "alice", AuthKey: []byte("wrong")}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong password login error = %v", err)
	}
	first, err := service.Login(ctx, protocol.LoginRequest{Username: "alice", AuthKey: setup.AuthKey, DeviceName: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	userID, err := service.Authenticate(ctx, first.AccessToken)
	if err != nil || userID == "" {
		t.Fatalf("Authenticate() = %q, %v", userID, err)
	}

	second, err := service.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, first.AccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old access token error = %v", err)
	}
	if _, err := service.Authenticate(ctx, second.AccessToken); err != nil {
		t.Fatalf("new access token rejected: %v", err)
	}
	if err := service.Logout(ctx, second.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, second.AccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("logged out access token error = %v", err)
	}
}

func TestServiceRejectsInvalidRegistration(t *testing.T) {
	service := NewService(store.NewMemory(), []byte("pepper"))
	err := service.Register(context.Background(), protocol.RegisterRequest{Username: "no"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Register() error = %v", err)
	}
}

func newTestVaultSetup(t *testing.T, username, password string) vaultcrypto.VaultSetup {
	t.Helper()
	setup, err := vaultcrypto.NewVaultSetup(username, password, protocol.KDFParameters{
		Time:        1,
		Memory:      8 * 1024,
		Parallelism: 1,
		KeyLength:   32,
	})
	if err != nil {
		t.Fatal(err)
	}
	return setup
}
