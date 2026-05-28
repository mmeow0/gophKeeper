package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

func TestSaveLoadDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	want := Profile{Server: "http://localhost:8080", LoginResponse: protocol.LoginResponse{
		Username: "alice", TokenPair: protocol.TokenPair{AccessToken: "token"},
	}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("session mode = %o, want 600", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != want.Username || got.Server != want.Server {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if err := Delete(path); err != nil {
		t.Fatal(err)
	}
	if err := Delete(path); err != nil {
		t.Fatal(err)
	}
}
