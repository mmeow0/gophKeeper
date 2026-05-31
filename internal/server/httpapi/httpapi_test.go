package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/auth"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
	"github.com/ajgultumerkina/gophkeeper/internal/server/vault"
)

func TestHandlerAuthVaultFlow(t *testing.T) {
	handler := newTestHandler()
	setup := newHTTPVaultSetup(t, "alice", "long master password")
	register := protocol.RegisterRequest{
		Username:        "alice",
		AuthSalt:        setup.AuthSalt,
		KDF:             setup.KDF,
		AuthKey:         setup.AuthKey,
		WrappedVaultKey: setup.WrappedVaultKey,
		WrapNonce:       setup.WrapNonce,
	}

	response := doJSON(t, handler, http.MethodPost, "/v1/auth/register", "", register)
	if response.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body %s", response.Code, response.Body.String())
	}
	response = doJSON(t, handler, http.MethodPost, "/v1/auth/register", "", register)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate register status = %d", response.Code)
	}

	response = doJSON(t, handler, http.MethodPost, "/v1/auth/login/parameters", "", protocol.LoginParametersRequest{Username: "alice"})
	if response.Code != http.StatusOK {
		t.Fatalf("login parameters status = %d", response.Code)
	}

	var login protocol.LoginResponse
	response = doJSON(t, handler, http.MethodPost, "/v1/auth/login", "", protocol.LoginRequest{Username: "alice", AuthKey: setup.AuthKey})
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", response.Code, response.Body.String())
	}
	decodeJSON(t, response, &login)

	secret := vaultcrypto.Secret{ID: "note", Kind: vaultcrypto.KindText, Name: "Note", Text: &vaultcrypto.TextSecret{Value: "secret"}}
	encrypted, err := vaultcrypto.EncryptSecret(setup.VaultKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	put := protocol.PutItemRequest{CryptoVersion: encrypted.CryptoVersion, Nonce: encrypted.Nonce, Ciphertext: encrypted.Ciphertext}
	response = doJSON(t, handler, http.MethodPut, "/v1/items/note", login.AccessToken, put)
	if response.Code != http.StatusOK {
		t.Fatalf("put status = %d, body %s", response.Code, response.Body.String())
	}
	var item protocol.EncryptedItem
	decodeJSON(t, response, &item)

	response = doJSON(t, handler, http.MethodGet, "/v1/items/note", login.AccessToken, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get status = %d", response.Code)
	}
	response = doJSON(t, handler, http.MethodGet, "/v1/sync?after=0&limit=1", login.AccessToken, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("sync status = %d", response.Code)
	}
	response = doJSON(t, handler, http.MethodDelete, "/v1/items/note", login.AccessToken, protocol.DeleteItemRequest{BaseVersion: item.Version})
	if response.Code != http.StatusOK {
		t.Fatalf("delete status = %d", response.Code)
	}
	response = doJSON(t, handler, http.MethodPost, "/v1/auth/logout", login.AccessToken, nil)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d", response.Code)
	}
}

func TestHandlerValidationFailures(t *testing.T) {
	handler := newTestHandler()
	response := doJSON(t, handler, http.MethodGet, "/health", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
	response = doRaw(t, handler, http.MethodPost, "/v1/auth/register", "", []byte("{bad"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", response.Code)
	}
	response = doJSON(t, handler, http.MethodGet, "/v1/sync", "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous sync status = %d", response.Code)
	}
	response = doJSON(t, handler, http.MethodPost, "/v1/auth/refresh", "", protocol.RefreshRequest{RefreshToken: "missing"})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad refresh status = %d", response.Code)
	}
}

func newTestHandler() http.Handler {
	repository := store.NewMemory()
	return New(auth.NewService(repository, []byte("test pepper")), vault.NewService(repository))
}

func newHTTPVaultSetup(t *testing.T, username, password string) vaultcrypto.VaultSetup {
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

func doJSON(t *testing.T, handler http.Handler, method, target, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return doRaw(t, handler, method, target, token, payload)
}

func doRaw(t *testing.T, handler http.Handler, method, target, token string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(payload))
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeJSON(t *testing.T, response *httptest.ResponseRecorder, value any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(value); err != nil {
		t.Fatal(err)
	}
}
