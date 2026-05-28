// Пакет api содержит HTTP-клиент для общения CLI с сервером GophKeeper.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

// Error описывает ошибку HTTP API, полученную от сервера GophKeeper.
type Error struct {
	Status  int
	Message string
}

// Error форматирует серверную ошибку для вывода в терминал.
func (e *Error) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Message)
}

// Client выполняет запросы к одному настроенному адресу сервера GophKeeper.
type Client struct {
	baseURL string
	http    *http.Client
}

// New проверяет адрес сервера и создаёт API-клиент. Обычный HTTP разрешён
// только для локальной разработки.
func New(serverURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid server URL")
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return nil, errors.New("server URL must use HTTPS except on localhost")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: parsed.String(), http: httpClient}, nil
}

// Register создаёт аккаунт и отправляет на сервер только подготовленный
// клиентом зашифрованный материал ключей.
func (c *Client) Register(ctx context.Context, request protocol.RegisterRequest) error {
	return c.do(ctx, http.MethodPost, "/v1/auth/register", "", request, nil, http.StatusCreated)
}

// LoginParameters получает параметры вывода ключей перед локальной обработкой
// мастер-пароля.
func (c *Client) LoginParameters(ctx context.Context, username string) (protocol.LoginParametersResponse, error) {
	var response protocol.LoginParametersResponse
	err := c.do(ctx, http.MethodPost, "/v1/auth/login/parameters", "", protocol.LoginParametersRequest{Username: username}, &response, http.StatusOK)
	return response, err
}

// Login отправляет производный ключ аутентификации и получает сессию вместе с
// зашифрованным ключом хранилища.
func (c *Client) Login(ctx context.Context, request protocol.LoginRequest) (protocol.LoginResponse, error) {
	var response protocol.LoginResponse
	err := c.do(ctx, http.MethodPost, "/v1/auth/login", "", request, &response, http.StatusOK)
	return response, err
}

// Refresh меняет текущий refresh-токен на новую пару токенов.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (protocol.TokenPair, error) {
	var response protocol.TokenPair
	err := c.do(ctx, http.MethodPost, "/v1/auth/refresh", "", protocol.RefreshRequest{RefreshToken: refreshToken}, &response, http.StatusOK)
	return response, err
}

// Logout отзывает сессию, которой сейчас пользуется клиент.
func (c *Client) Logout(ctx context.Context, accessToken string) error {
	return c.do(ctx, http.MethodPost, "/v1/auth/logout", accessToken, nil, nil, http.StatusNoContent)
}

// GetItem получает одну зашифрованную запись хранилища по идентификатору.
func (c *Client) GetItem(ctx context.Context, accessToken, id string) (protocol.EncryptedItem, error) {
	var response protocol.EncryptedItem
	err := c.do(ctx, http.MethodGet, "/v1/items/"+url.PathEscape(id), accessToken, nil, &response, http.StatusOK)
	return response, err
}

// PutItem создаёт или обновляет одну зашифрованную запись.
func (c *Client) PutItem(ctx context.Context, accessToken string, item protocol.EncryptedItem, baseVersion int64) (protocol.EncryptedItem, error) {
	var response protocol.EncryptedItem
	request := protocol.PutItemRequest{
		BaseVersion:   baseVersion,
		CryptoVersion: item.CryptoVersion,
		Nonce:         item.Nonce,
		Ciphertext:    item.Ciphertext,
	}
	err := c.do(ctx, http.MethodPut, "/v1/items/"+url.PathEscape(item.ID), accessToken, request, &response, http.StatusOK)
	return response, err
}

// DeleteItem фиксирует удаление записи на указанной версии, чтобы другие
// клиенты тоже увидели метку удаления при синхронизации.
func (c *Client) DeleteItem(ctx context.Context, accessToken, id string, baseVersion int64) (protocol.EncryptedItem, error) {
	var response protocol.EncryptedItem
	err := c.do(ctx, http.MethodDelete, "/v1/items/"+url.PathEscape(id), accessToken, protocol.DeleteItemRequest{BaseVersion: baseVersion}, &response, http.StatusOK)
	return response, err
}

const syncPageLimit = 500

// Sync получает все изменения после указанной ревизии и сам дочитывает страницы
// сервера, чтобы CLI не потерял записи при большом хранилище.
func (c *Client) Sync(ctx context.Context, accessToken string, after int64) (protocol.SyncResponse, error) {
	var combined protocol.SyncResponse
	cursor := after
	for {
		page, err := c.syncPage(ctx, accessToken, cursor, syncPageLimit)
		if err != nil {
			return protocol.SyncResponse{}, err
		}
		combined.Items = append(combined.Items, page.Items...)
		combined.CurrentRevision = page.CurrentRevision
		if page.CurrentRevision <= cursor || len(page.Items) < syncPageLimit {
			return combined, nil
		}
		cursor = page.CurrentRevision
	}
}

func (c *Client) syncPage(ctx context.Context, accessToken string, after int64, limit int) (protocol.SyncResponse, error) {
	var response protocol.SyncResponse
	path := "/v1/sync?after=" + strconv.FormatInt(after, 10) + "&limit=" + strconv.Itoa(limit)
	err := c.do(ctx, http.MethodGet, path, accessToken, nil, &response, http.StatusOK)
	return response, err
}

func (c *Client) do(ctx context.Context, method, path, token string, request, response any, expected int) error {
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	result, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	if result.StatusCode != expected {
		var serverError protocol.ErrorResponse
		if err := json.NewDecoder(result.Body).Decode(&serverError); err != nil || serverError.Error == "" {
			serverError.Error = result.Status
		}
		return &Error{Status: result.StatusCode, Message: serverError.Error}
	}
	if response == nil || expected == http.StatusNoContent || expected == http.StatusCreated {
		return nil
	}
	return json.NewDecoder(result.Body).Decode(response)
}
