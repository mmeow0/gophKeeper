package command

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientapi "github.com/ajgultumerkina/gophkeeper/internal/client/api"
	"github.com/ajgultumerkina/gophkeeper/internal/server/auth"
	"github.com/ajgultumerkina/gophkeeper/internal/server/httpapi"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
	"github.com/ajgultumerkina/gophkeeper/internal/server/vault"
)

func TestCLIWorkflowForAllSecretKinds(t *testing.T) {
	client := testRemote(t)
	sessionPath := filepath.Join(t.TempDir(), "session.json")
	run := func(input string, passwords []string, args ...string) string {
		t.Helper()
		var output bytes.Buffer
		index := 0
		app := New(strings.NewReader(input), &output, &output, func(string) (string, error) {
			if index >= len(passwords) {
				return "", fmt.Errorf("unexpected password request")
			}
			value := passwords[index]
			index++
			return value, nil
		}, sessionPath)
		app.newRemote = func(string) (remote, error) { return client, nil }
		if err := app.Run(context.Background(), args); err != nil {
			t.Fatalf("%v failed: %v\noutput: %s", args, err, output.String())
		}
		return output.String()
	}

	const password = "long master password"
	run("", []string{password, password}, "register", "--server", "http://localhost", "--user", "Alice")
	run("", []string{password}, "login", "--server", "http://localhost", "--user", "alice")

	loginOutput := run("mail-user\n", []string{"mail-password", password}, "add", "login", "--name", "Mail", "--meta", "personal")
	loginID := storedID(t, loginOutput)
	if got := run("", []string{password}, "get", loginID); !strings.Contains(got, "mail-password") {
		t.Fatalf("login get output = %q", got)
	}

	textOutput := run("", []string{"private note", password}, "add", "text", "--name", "Note")
	if got := run("", []string{password}, "get", storedID(t, textOutput)); !strings.Contains(got, "private note") {
		t.Fatalf("text get output = %q", got)
	}

	cardOutput := run("Alice Holder\n12/30\n", []string{"4111111111111111", "123", password}, "add", "card", "--name", "Card")
	if got := run("", []string{password}, "get", storedID(t, cardOutput)); !strings.Contains(got, "4111111111111111") {
		t.Fatalf("card get output = %q", got)
	}

	source := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(source, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	binaryOutput := run("", []string{password}, "add", "binary", "--name", "Blob", "--file", source)
	binaryID := storedID(t, binaryOutput)
	destination := filepath.Join(t.TempDir(), "restored.bin")
	run("", []string{password}, "get", "--out", destination, binaryID)
	restored, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(restored, []byte{1, 2, 3}) {
		t.Fatalf("restored binary = %v, %v", restored, err)
	}

	otpOutput := run("", []string{password}, "add", "otp", "--name", "GitHub", "--uri", "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	if code := strings.TrimSpace(run("", []string{password}, "otp", "code", storedID(t, otpOutput))); len(code) != 6 {
		t.Fatalf("OTP output = %q", code)
	}

	if listing := run("", []string{password}, "list"); !strings.Contains(listing, "Mail") || !strings.Contains(listing, "GitHub") {
		t.Fatalf("list output = %q", listing)
	}
	run("", []string{password}, "edit", "--name", "Email", "--meta", "updated", loginID)
	if edited := run("", []string{password}, "get", loginID); !strings.Contains(edited, "Email") {
		t.Fatalf("edit output = %q", edited)
	}
	run("", nil, "refresh")
	run("", []string{password}, "delete", loginID)
	run("", nil, "logout")
}

func TestCLIUsageAndValidation(t *testing.T) {
	var output bytes.Buffer
	app := New(strings.NewReader(""), &output, &output, func(string) (string, error) { return "short", nil }, filepath.Join(t.TempDir(), "session"))
	if err := app.Run(context.Background(), nil); err != nil || !strings.Contains(output.String(), "Usage:") {
		t.Fatalf("usage result: %v, %q", err, output.String())
	}
	if err := app.Run(context.Background(), []string{"unknown"}); err == nil {
		t.Fatal("expected unknown command error")
	}
	if err := app.Run(context.Background(), []string{"register", "-user", "alice"}); err == nil {
		t.Fatal("expected legacy single-dash flag syntax error")
	}
	if err := app.Run(context.Background(), []string{"register", "--user", "alice"}); err == nil {
		t.Fatal("expected weak password error")
	}
	output.Reset()
	if err := app.Run(context.Background(), []string{"version"}); err != nil || !strings.Contains(output.String(), "GophKeeper") {
		t.Fatalf("version result: %v, %q", err, output.String())
	}
}

func testRemote(t *testing.T) *clientapi.Client {
	t.Helper()
	repository := store.NewMemory()
	handler := httpapi.New(auth.NewService(repository, []byte("test pepper")), vault.NewService(repository))
	client, err := clientapi.New("http://localhost", &http.Client{Transport: localTransport{handler}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type localTransport struct {
	handler http.Handler
}

func (transport localTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func storedID(t *testing.T, output string) string {
	t.Helper()
	parts := strings.Fields(output)
	for index, part := range parts {
		if part == "secret" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	t.Fatalf("cannot find stored ID in %q", output)
	return ""
}
