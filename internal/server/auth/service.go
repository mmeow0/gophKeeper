// Пакет auth содержит серверную бизнес-логику регистрации, входа и
// bearer-сессий.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{3,128}$`)

// ErrUnauthorized означает, что учётные данные неверны, истекли или были
// отозваны.
var ErrUnauthorized = errors.New("unauthorized")

// ErrInvalidInput означает некорректные данные регистрации или аутентификации.
var ErrInvalidInput = errors.New("invalid input")

// Service выполняет операции с аккаунтами и токен-сессиями.
type Service struct {
	repository store.Repository
	pepper     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
}

// NewService создаёт сервис аутентификации. Pepper должен быть отдельным
// секретом окружения и не должен храниться в базе данных.
func NewService(repository store.Repository, pepper []byte) *Service {
	return &Service{
		repository: repository,
		pepper:     append([]byte(nil), pepper...),
		accessTTL:  time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
		now:        time.Now,
	}
}

// Register сохраняет проверочные данные аутентификации и зашифрованный ключ
// пользовательского хранилища.
func (s *Service) Register(ctx context.Context, request protocol.RegisterRequest) error {
	username := normalizeUsername(request.Username)
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("%w: username must contain 3-128 allowed characters", ErrInvalidInput)
	}
	if len(request.AuthSalt) != 16 || len(request.AuthKey) != 32 || len(request.WrappedVaultKey) != 48 || len(request.WrapNonce) != 24 {
		return fmt.Errorf("%w: invalid encrypted registration material", ErrInvalidInput)
	}
	if request.KDF.Time < 1 || request.KDF.Time > 10 ||
		request.KDF.Memory < 8*1024 || request.KDF.Memory > 1024*1024 ||
		request.KDF.Parallelism < 1 || request.KDF.Parallelism > 16 ||
		request.KDF.KeyLength != 32 {
		return fmt.Errorf("%w: invalid KDF parameters", ErrInvalidInput)
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	return s.repository.CreateUser(ctx, store.User{
		ID:              id,
		Username:        username,
		AuthSalt:        request.AuthSalt,
		KDF:             request.KDF,
		AuthVerifier:    s.verifier(request.AuthKey),
		WrappedVaultKey: request.WrappedVaultKey,
		WrapNonce:       request.WrapNonce,
		CreatedAt:       s.now().UTC(),
	})
}

// LoginParameters возвращает публичные параметры KDF, чтобы клиент мог вывести
// ключи из мастер-пароля локально.
func (s *Service) LoginParameters(ctx context.Context, username string) (protocol.LoginParametersResponse, error) {
	user, err := s.repository.UserByUsername(ctx, normalizeUsername(username))
	if err != nil {
		return protocol.LoginParametersResponse{}, ErrUnauthorized
	}
	return protocol.LoginParametersResponse{AuthSalt: user.AuthSalt, KDF: user.KDF}, nil
}

// Login проверяет ключ аутентификации и выдаёт bearer-токены.
func (s *Service) Login(ctx context.Context, request protocol.LoginRequest) (protocol.LoginResponse, error) {
	user, err := s.repository.UserByUsername(ctx, normalizeUsername(request.Username))
	if err != nil || !hmac.Equal(user.AuthVerifier, s.verifier(request.AuthKey)) {
		return protocol.LoginResponse{}, ErrUnauthorized
	}
	tokens, err := s.issueSession(ctx, user.ID, request.DeviceName)
	if err != nil {
		return protocol.LoginResponse{}, err
	}
	return protocol.LoginResponse{
		TokenPair:       tokens,
		Username:        user.Username,
		AuthSalt:        user.AuthSalt,
		KDF:             user.KDF,
		WrappedVaultKey: user.WrappedVaultKey,
		WrapNonce:       user.WrapNonce,
	}, nil
}

// Authenticate проверяет access-токен и возвращает идентификатор его владельца.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (string, error) {
	session, err := s.repository.SessionByAccessHash(ctx, tokenHash(accessToken))
	if err != nil || session.RevokedAt != nil || !s.now().Before(session.AccessExpiresAt) {
		return "", ErrUnauthorized
	}
	return session.UserID, nil
}

// Refresh меняет действующий refresh-токен на новую пару access/refresh.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (protocol.TokenPair, error) {
	session, err := s.repository.SessionByRefreshHash(ctx, tokenHash(refreshToken))
	if err != nil || session.RevokedAt != nil || !s.now().Before(session.RefreshExpiresAt) {
		return protocol.TokenPair{}, ErrUnauthorized
	}
	if err := s.repository.RevokeSession(ctx, session.ID, s.now().UTC()); err != nil {
		return protocol.TokenPair{}, err
	}
	return s.issueSession(ctx, session.UserID, session.DeviceName)
}

// Logout отзывает сессию, которая соответствует переданному access-токену.
func (s *Service) Logout(ctx context.Context, accessToken string) error {
	session, err := s.repository.SessionByAccessHash(ctx, tokenHash(accessToken))
	if err != nil || session.RevokedAt != nil {
		return ErrUnauthorized
	}
	return s.repository.RevokeSession(ctx, session.ID, s.now().UTC())
}

func (s *Service) verifier(authKey []byte) []byte {
	mac := hmac.New(sha256.New, s.pepper)
	mac.Write(authKey)
	return mac.Sum(nil)
}

func (s *Service) issueSession(ctx context.Context, userID, deviceName string) (protocol.TokenPair, error) {
	access, err := randomToken()
	if err != nil {
		return protocol.TokenPair{}, err
	}
	refresh, err := randomToken()
	if err != nil {
		return protocol.TokenPair{}, err
	}
	id, err := randomID()
	if err != nil {
		return protocol.TokenPair{}, err
	}
	now := s.now().UTC()
	session := store.Session{
		ID:               id,
		UserID:           userID,
		AccessTokenHash:  tokenHash(access),
		RefreshTokenHash: tokenHash(refresh),
		AccessExpiresAt:  now.Add(s.accessTTL),
		RefreshExpiresAt: now.Add(s.refreshTTL),
		DeviceName:       deviceName,
		CreatedAt:        now,
	}
	if err := s.repository.CreateSession(ctx, session); err != nil {
		return protocol.TokenPair{}, err
	}
	return protocol.TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresAt: session.AccessExpiresAt}, nil
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomID() (string, error) {
	return randomToken()
}
