package app

import (
	"context"
	"os"
	"testing"

	"github.com/ajgultumerkina/gophkeeper/internal/server/config"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
)

func TestInitializeAppInMemoryMode(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"server", "-memory", "-listen", "127.0.0.1:0"}
	t.Setenv("DATABASE_URL", "")
	t.Setenv("GOPHKEEPER_PEPPER", "")

	app, err := InitializeApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.cfg == nil || !app.cfg.MemoryStorage || app.server.Addr != "127.0.0.1:0" || app.logger == nil {
		t.Fatalf("app = %#v", app)
	}
}

func TestDevelopmentRepositoryAndPepper(t *testing.T) {
	cfg := &config.Config{MemoryStorage: true}
	repository, closeRepository, err := repository(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRepository()
	if _, ok := repository.(*store.Memory); !ok {
		t.Fatalf("repository type = %T, want *store.Memory", repository)
	}
	pepper, generated, err := serverPepper(cfg)
	if err != nil || len(pepper) != 32 || !generated {
		t.Fatalf("serverPepper(memory) = %v, %v, %v", pepper, generated, err)
	}
}

func TestProductionPepperRequirement(t *testing.T) {
	if _, _, err := serverPepper(&config.Config{}); err == nil {
		t.Fatal("expected missing pepper error")
	}
	pepper, generated, err := serverPepper(&config.Config{Pepper: "configured"})
	if err != nil || generated || string(pepper) != "configured" {
		t.Fatalf("serverPepper(production) = %q, %v, %v", pepper, generated, err)
	}
}

func TestMaskDSN(t *testing.T) {
	got := maskDSN("postgres://user:secret@localhost:5432/gophkeeper?sslmode=disable")
	want := "postgres://user:%2A%2A%2A@localhost:5432/gophkeeper?sslmode=disable"
	if got != want {
		t.Fatalf("maskDSN() = %q, want %q", got, want)
	}
	if got := maskDSN("not a url"); got == "" {
		t.Fatal("maskDSN returned empty string")
	}
}
