package otp

import (
	"testing"
	"time"

	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
)

func TestGenerateRFC6238(t *testing.T) {
	config := vaultcrypto.OTPSecret{
		Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm: "SHA1",
		Digits:    8,
		Period:    30,
	}
	code, err := Generate(config, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "94287082" {
		t.Fatalf("got %q, want RFC vector %q", code, "94287082")
	}
}

func TestParseURI(t *testing.T) {
	config, err := ParseURI("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	if err != nil {
		t.Fatal(err)
	}
	if config.Issuer != "GitHub" || config.Account != "GitHub:alice" || config.Digits != 6 {
		t.Fatalf("unexpected parsed config: %#v", config)
	}
}
