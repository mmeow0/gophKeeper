// Пакет httpapi публикует серверные сервисы GophKeeper через версионированное
// JSON HTTP API.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/auth"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
	"github.com/ajgultumerkina/gophkeeper/internal/server/vault"
)

type userIDContextKey struct{}

// Handler направляет HTTP-запросы в сервисы аутентификации и зашифрованного
// хранилища.
type Handler struct {
	auth  *auth.Service
	vault *vault.Service
}

// New создаёт HTTP-handler для всех публичных и защищённых маршрутов API.
func New(authService *auth.Service, vaultService *vault.Service) http.Handler {
	handler := &Handler{auth: authService, vault: vaultService}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.health)
	mux.HandleFunc("POST /v1/auth/register", handler.register)
	mux.HandleFunc("POST /v1/auth/login/parameters", handler.loginParameters)
	mux.HandleFunc("POST /v1/auth/login", handler.login)
	mux.HandleFunc("POST /v1/auth/refresh", handler.refresh)
	mux.Handle("POST /v1/auth/logout", handler.authorize(http.HandlerFunc(handler.logout)))
	mux.Handle("GET /v1/items/{id}", handler.authorize(http.HandlerFunc(handler.getItem)))
	mux.Handle("PUT /v1/items/{id}", handler.authorize(http.HandlerFunc(handler.putItem)))
	mux.Handle("DELETE /v1/items/{id}", handler.authorize(http.HandlerFunc(handler.deleteItem)))
	mux.Handle("GET /v1/sync", handler.authorize(http.HandlerFunc(handler.sync)))
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var request protocol.RegisterRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if err := h.auth.Register(r.Context(), request); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) loginParameters(w http.ResponseWriter, r *http.Request) {
	var request protocol.LoginParametersRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	response, err := h.auth.LoginParameters(r.Context(), request.Username)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var request protocol.LoginRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	response, err := h.auth.Login(r.Context(), request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var request protocol.RefreshRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	response, err := h.auth.Refresh(r.Context(), request.RefreshToken)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.Logout(r.Context(), bearerToken(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getItem(w http.ResponseWriter, r *http.Request) {
	item, err := h.vault.Get(r.Context(), userID(r.Context()), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) putItem(w http.ResponseWriter, r *http.Request) {
	var request protocol.PutItemRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	item, err := h.vault.Put(r.Context(), userID(r.Context()), r.PathValue("id"), request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) deleteItem(w http.ResponseWriter, r *http.Request) {
	var request protocol.DeleteItemRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	item, err := h.vault.Delete(r.Context(), userID(r.Context()), r.PathValue("id"), request)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	after, err := integerQuery(r, "after", 0)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "invalid after query parameter"})
		return
	}
	limit, err := integerQuery(r, "limit", 100)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "invalid limit query parameter"})
		return
	}
	response, err := h.vault.Sync(r.Context(), userID(r.Context()), int64(after), limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, auth.ErrUnauthorized)
			return
		}
		id, err := h.auth.Authenticate(r.Context(), token)
		if err != nil {
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDContextKey{}, id)))
	})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 24<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "invalid JSON request"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "request must contain one JSON object"})
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "internal server error"
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		status, message = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, auth.ErrInvalidInput), errors.Is(err, vault.ErrInvalidInput):
		status, message = http.StatusBadRequest, err.Error()
	case errors.Is(err, store.ErrAlreadyExists):
		status, message = http.StatusConflict, "username already exists"
	case errors.Is(err, store.ErrConflict):
		status, message = http.StatusConflict, "item version conflict"
	case errors.Is(err, store.ErrNotFound):
		status, message = http.StatusNotFound, "not found"
	}
	writeJSON(w, status, protocol.ErrorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func userID(ctx context.Context) string {
	id, _ := ctx.Value(userIDContextKey{}).(string)
	return id
}

func integerQuery(r *http.Request, key string, fallback int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}
