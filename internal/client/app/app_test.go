package app

import (
	"os"
	"testing"
)

func TestInitializeAppVersionCommand(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"gophkeeper", "version"}

	app, err := InitializeApp()
	if err != nil {
		t.Fatal(err)
	}
	if app.command == nil || len(app.args) != 1 || app.args[0] != "version" {
		t.Fatalf("app = %#v", app)
	}
	if err := app.Run(); err != nil {
		t.Fatal(err)
	}
	app.Close()
}

func TestInitializeAppRegularCommand(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"gophkeeper", "help"}

	app, err := InitializeApp()
	if err != nil {
		t.Fatal(err)
	}
	if app.command == nil || len(app.args) != 1 || app.args[0] != "help" {
		t.Fatalf("app = %#v", app)
	}
	app.Close()
}
