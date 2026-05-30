package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientapi "github.com/ajgultumerkina/gophkeeper/internal/client/api"
	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/auth"
	"github.com/ajgultumerkina/gophkeeper/internal/server/httpapi"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
	"github.com/ajgultumerkina/gophkeeper/internal/server/vault"
)

func TestEncryptedSyncConflictAndDeletion(t *testing.T) {
	client := newClient(t)
	first, key := registerAndLogin(t, client, "alice", "alice password")
	second, secondKey := login(t, client, "alice", "alice password")

	secret := vaultcrypto.Secret{ID: "email", Kind: vaultcrypto.KindLogin, Name: "mail", Login: &vaultcrypto.LoginSecret{Username: "alice", Password: "secret"}}
	encrypted, err := vaultcrypto.EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.PutItem(context.Background(), first.AccessToken, encrypted, 0)
	if err != nil {
		t.Fatal(err)
	}
	changes := syncItems(t, client, second.AccessToken, 0)
	if len(changes) != 1 || changes[0].Revision != 1 {
		t.Fatalf("unexpected initial sync: %#v", changes)
	}
	decrypted, err := vaultcrypto.DecryptSecret(secondKey, changes[0])
	if err != nil || decrypted.Login.Password != "secret" {
		t.Fatalf("second client could not decrypt synchronized secret: %#v, %v", decrypted, err)
	}

	secret.Name = "new name"
	changedEnvelope, err := vaultcrypto.EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.PutItem(context.Background(), first.AccessToken, changedEnvelope, created.Version)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutItem(context.Background(), second.AccessToken, encrypted, created.Version)
	assertStatus(t, err, http.StatusConflict)

	deleted, err := client.DeleteItem(context.Background(), first.AccessToken, updated.ID, updated.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Deleted || deleted.Revision != 3 {
		t.Fatalf("unexpected tombstone: %#v", deleted)
	}
	changes = syncItems(t, client, second.AccessToken, updated.Revision)
	if len(changes) != 1 || !changes[0].Deleted {
		t.Fatalf("expected synchronized tombstone: %#v", changes)
	}
}

func TestUserIsolationRefreshAndLogout(t *testing.T) {
	client := newClient(t)
	alice, key := registerAndLogin(t, client, "alice", "alice password")
	bob, _ := registerAndLogin(t, client, "bob", "bobs password")
	item, err := vaultcrypto.EncryptSecret(key, vaultcrypto.Secret{ID: "private", Kind: vaultcrypto.KindText, Name: "note", Text: &vaultcrypto.TextSecret{Value: "mine"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutItem(context.Background(), alice.AccessToken, item, 0); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetItem(context.Background(), bob.AccessToken, "private")
	assertStatus(t, err, http.StatusNotFound)

	tokens, err := client.Refresh(context.Background(), alice.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetItem(context.Background(), alice.AccessToken, "private")
	assertStatus(t, err, http.StatusUnauthorized)
	if _, err := client.GetItem(context.Background(), tokens.AccessToken, "private"); err != nil {
		t.Fatal(err)
	}
	if err := client.Logout(context.Background(), tokens.AccessToken); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetItem(context.Background(), tokens.AccessToken, "private")
	assertStatus(t, err, http.StatusUnauthorized)
}

func TestHTTPValidationFailures(t *testing.T) {
	client, raw := clients(t)
	response, err := raw.Get("http://localhost/health")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %v, %v", response, err)
	}
	response.Body.Close()

	request, _ := http.NewRequest(http.MethodPost, "http://localhost/v1/auth/register", bytes.NewBufferString("{bad"))
	response, err = raw.Do(request)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed registration status = %v, %v", response, err)
	}
	response.Body.Close()

	request, _ = http.NewRequest(http.MethodGet, "http://localhost/v1/sync", nil)
	response, err = raw.Do(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous sync status = %v, %v", response, err)
	}
	response.Body.Close()

	err = client.Register(context.Background(), protocol.RegisterRequest{Username: "bad"})
	assertStatus(t, err, http.StatusBadRequest)

	login, _ := registerAndLogin(t, client, "alice", "alice password")
	params := protocol.KDFParameters{Time: 1, Memory: 8 * 1024, Parallelism: 1, KeyLength: 32}
	setup, err := vaultcrypto.NewVaultSetup("alice", "other password", params)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register(context.Background(), protocol.RegisterRequest{
		Username: "alice", AuthSalt: setup.AuthSalt, KDF: setup.KDF, AuthKey: setup.AuthKey,
		WrappedVaultKey: setup.WrappedVaultKey, WrapNonce: setup.WrapNonce,
	})
	assertStatus(t, err, http.StatusConflict)

	request, _ = http.NewRequest(http.MethodGet, "http://localhost/v1/sync?after=nope", nil)
	request.Header.Set("Authorization", "Bearer "+login.AccessToken)
	response, err = raw.Do(request)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid sync query status = %v, %v", response, err)
	}
	response.Body.Close()

	body, _ := json.Marshal(protocol.PutItemRequest{CryptoVersion: 1, Nonce: []byte("short"), Ciphertext: []byte("x")})
	request, _ = http.NewRequest(http.MethodPut, "http://localhost/v1/items/bad", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+login.AccessToken)
	response, err = raw.Do(request)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid envelope status = %v, %v", response, err)
	}
	response.Body.Close()
}

func newClient(t *testing.T) *clientapi.Client {
	t.Helper()
	client, _ := clients(t)
	return client
}

func syncItems(t *testing.T, client *clientapi.Client, accessToken string, after int64) []protocol.EncryptedItem {
	t.Helper()
	var items []protocol.EncryptedItem
	for item, err := range client.Sync(context.Background(), accessToken, after) {
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	return items
}

func clients(t *testing.T) (*clientapi.Client, *http.Client) {
	t.Helper()
	repository := store.NewMemory()
	handler := httpapi.New(auth.NewService(repository, []byte("test pepper")), vault.NewService(repository))
	httpClient := &http.Client{Transport: handlerTransport{handler: handler}}
	client, err := clientapi.New("http://localhost", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return client, httpClient
}

type handlerTransport struct {
	handler http.Handler
}

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func registerAndLogin(t *testing.T, client *clientapi.Client, username, password string) (protocol.LoginResponse, []byte) {
	t.Helper()
	params := protocol.KDFParameters{Time: 1, Memory: 8 * 1024, Parallelism: 1, KeyLength: 32}
	setup, err := vaultcrypto.NewVaultSetup(username, password, params)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Register(context.Background(), protocol.RegisterRequest{
		Username: username, AuthSalt: setup.AuthSalt, KDF: setup.KDF, AuthKey: setup.AuthKey,
		WrappedVaultKey: setup.WrappedVaultKey, WrapNonce: setup.WrapNonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, key := login(t, client, username, password)
	return response, key
}

func login(t *testing.T, client *clientapi.Client, username, password string) (protocol.LoginResponse, []byte) {
	t.Helper()
	params, err := client.LoginParameters(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	authKey, wrapKey, err := vaultcrypto.DeriveKeys(password, params.AuthSalt, params.KDF)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Login(context.Background(), protocol.LoginRequest{Username: username, AuthKey: authKey})
	if err != nil {
		t.Fatal(err)
	}
	key, err := vaultcrypto.UnwrapVaultKey(response.WrappedVaultKey, response.WrapNonce, wrapKey, username)
	if err != nil {
		t.Fatal(err)
	}
	return response, key
}

func assertStatus(t *testing.T, err error, status int) {
	t.Helper()
	var apiError *clientapi.Error
	if !errors.As(err, &apiError) || apiError.Status != status {
		t.Fatalf("got error %v, want HTTP status %d", err, status)
	}
}
