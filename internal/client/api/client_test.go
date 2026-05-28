package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

func TestSyncFollowsServerPages(t *testing.T) {
	var afters []int64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header = %q", request.Header.Get("Authorization"))
		}
		after, err := strconv.ParseInt(request.URL.Query().Get("after"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if request.URL.Query().Get("limit") != "500" {
			t.Fatalf("limit query = %q", request.URL.Query().Get("limit"))
		}
		afters = append(afters, after)

		response := protocol.SyncResponse{CurrentRevision: after}
		switch after {
		case 0:
			response.CurrentRevision = 500
			for revision := int64(1); revision <= 500; revision++ {
				response.Items = append(response.Items, protocol.EncryptedItem{ID: strconv.FormatInt(revision, 10), Revision: revision})
			}
		case 500:
			response.CurrentRevision = 501
			response.Items = []protocol.EncryptedItem{{ID: "501", Revision: 501}}
		default:
			t.Fatalf("unexpected sync cursor %d", after)
		}
		return jsonResponse(http.StatusOK, response)
	})
	client, err := New("http://localhost", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.Sync(context.Background(), "token", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentRevision != 501 || len(got.Items) != 501 {
		t.Fatalf("Sync() = revision %d, %d items", got.CurrentRevision, len(got.Items))
	}
	if !reflect.DeepEqual(afters, []int64{0, 500}) {
		t.Fatalf("sync cursors = %v", afters)
	}
}

func TestNewRejectsPlainHTTPForRemoteHosts(t *testing.T) {
	if _, err := New("http://example.com", nil); err == nil {
		t.Fatal("expected remote HTTP URL to be rejected")
	}
	if _, err := New("http://localhost:8080", nil); err != nil {
		t.Fatalf("localhost HTTP should be accepted: %v", err)
	}
}

func TestErrorFormatsServerResponse(t *testing.T) {
	transport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusTeapot, protocol.ErrorResponse{Error: "short and stout"})
	})
	client, err := New("http://localhost", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Logout(context.Background(), "token")
	apiError, ok := err.(*Error)
	if !ok || apiError.Status != http.StatusTeapot || !strings.Contains(apiError.Error(), "short and stout") {
		t.Fatalf("Logout() error = %#v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func jsonResponse(status int, value any) (*http.Response, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       ioNopCloser{Reader: strings.NewReader(string(encoded))},
	}, nil
}

type ioNopCloser struct {
	*strings.Reader
}

func (closer ioNopCloser) Close() error {
	return nil
}
