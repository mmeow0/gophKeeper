package vaultcrypto

import (
	"testing"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

func testKDF() protocol.KDFParameters {
	return protocol.KDFParameters{Time: 1, Memory: 8 * 1024, Parallelism: 1, KeyLength: 32}
}

func TestVaultSetupAndSecretRoundTrip(t *testing.T) {
	setup, err := NewVaultSetup("alice", "strong password", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	_, wrapKey, err := DeriveKeys("strong password", setup.AuthSalt, setup.KDF)
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := UnwrapVaultKey(setup.WrappedVaultKey, setup.WrapNonce, wrapKey, "alice")
	if err != nil {
		t.Fatal(err)
	}

	secret := Secret{ID: "item", Kind: KindLogin, Name: "mail", Login: &LoginSecret{Username: "a", Password: "p"}}
	item, err := EncryptSecret(vaultKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSecret(vaultKey, item)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login.Password != secret.Login.Password || got.Name != secret.Name {
		t.Fatalf("got %#v, want %#v", got, secret)
	}
}

func TestWrongPasswordAndTamperAreRejected(t *testing.T) {
	setup, err := NewVaultSetup("alice", "right password", testKDF())
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := DeriveKeys("wrong password", setup.AuthSalt, setup.KDF)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapVaultKey(setup.WrappedVaultKey, setup.WrapNonce, wrongKey, "alice"); err == nil {
		t.Fatal("expected wrong password failure")
	}

	item, err := EncryptSecret(setup.VaultKey, Secret{ID: "id", Name: "note", Kind: KindText, Text: &TextSecret{Value: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	item.Ciphertext[0] ^= 0xff
	if _, err := DecryptSecret(setup.VaultKey, item); err == nil {
		t.Fatal("expected tampering failure")
	}
}

func TestValidateSecret(t *testing.T) {
	tests := []Secret{
		{ID: "1", Name: "x", Kind: KindLogin, Login: &LoginSecret{Password: "p"}},
		{ID: "2", Name: "x", Kind: KindText, Text: &TextSecret{}},
		{ID: "3", Name: "x", Kind: KindBinary, Binary: &BinarySecret{}},
		{ID: "4", Name: "x", Kind: KindCard, Card: &CardSecret{Number: "1"}},
		{ID: "5", Name: "x", Kind: KindOTP, OTP: &OTPSecret{Secret: "ABC"}},
	}
	for _, secret := range tests {
		if err := ValidateSecret(secret); err != nil {
			t.Errorf("ValidateSecret(%s): %v", secret.Kind, err)
		}
	}
	if err := ValidateSecret(Secret{ID: "x", Name: "x", Kind: KindLogin}); err == nil {
		t.Fatal("expected missing payload error")
	}
}

func TestPublicDefaultsIDsAndValidationFailures(t *testing.T) {
	if params := DefaultKDFParameters(); params.KeyLength != 32 || params.Memory < 8*1024 {
		t.Fatalf("unsafe defaults: %#v", params)
	}
	first, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewID()
	if err != nil || first == second || len(first) != 32 {
		t.Fatalf("IDs = %q and %q, err = %v", first, second, err)
	}
	if _, _, err := DeriveKeys("password", []byte("short"), testKDF()); err == nil {
		t.Fatal("expected salt validation error")
	}
	bad := testKDF()
	bad.Memory = 1
	if _, _, err := DeriveKeys("password", []byte("1234567890123456"), bad); err == nil {
		t.Fatal("expected KDF validation error")
	}
	if _, err := EncryptSecret(make([]byte, 32), Secret{Name: "missing-id", Kind: KindText, Text: &TextSecret{}}); err == nil {
		t.Fatal("expected missing ID error")
	}
}
