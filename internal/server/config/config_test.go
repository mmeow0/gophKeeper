package config

import (
	"errors"
	"testing"
)

func TestNewConfigFromArgsUsesMemoryMode(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("GOPHKEEPER_PEPPER", "")

	cfg, err := NewConfigFromArgs([]string{"-memory", "-listen", ":9090", "-log-level", "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MemoryStorage || cfg.RunAddress != ":9090" || cfg.LogLevel != "debug" {
		t.Fatalf("cfg = %#v", cfg)
	}
}

func TestNewConfigFromArgsRequiresProductionSecrets(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("GOPHKEEPER_PEPPER", "")
	if _, err := NewConfigFromArgs(nil); !errors.Is(err, ErrEmptyDatabaseURL) {
		t.Fatalf("missing database error = %v", err)
	}

	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost/db")
	if _, err := NewConfigFromArgs(nil); !errors.Is(err, ErrEmptyPepper) {
		t.Fatalf("missing pepper error = %v", err)
	}
}

func TestNewConfigFromArgsReadsEnvAndFlags(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://env:pass@localhost/db")
	t.Setenv("GOPHKEEPER_PEPPER", "pepper")
	t.Setenv("GOPHKEEPER_LISTEN", ":8181")
	t.Setenv("GOPHKEEPER_MEMORY", "false")

	cfg, err := NewConfigFromArgs([]string{"-listen", ":8282"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RunAddress != ":8282" || cfg.DatabaseURL == "" || cfg.Pepper != "pepper" {
		t.Fatalf("cfg = %#v", cfg)
	}
}

func TestValidateRejectsBadTLSPairAndEmptyAddress(t *testing.T) {
	err := (&Config{RunAddress: ":8080", MemoryStorage: true, TLSCertFile: "cert.pem"}).Validate()
	if !errors.Is(err, ErrIncompleteTLS) {
		t.Fatalf("TLS error = %v", err)
	}
	err = (&Config{MemoryStorage: true}).Validate()
	if !errors.Is(err, ErrEmptyRunAddress) {
		t.Fatalf("address error = %v", err)
	}
}
