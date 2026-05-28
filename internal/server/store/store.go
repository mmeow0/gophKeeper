// Пакет store задаёт границу хранения для серверной аутентификации и
// синхронизации зашифрованного хранилища.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

var (
	// ErrNotFound означает, что запрошенная сущность не найдена.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists означает, что уникальная сущность уже создана.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict означает, что для изменения передана устаревшая версия записи.
	ErrConflict = errors.New("item version conflict")
)

// User хранит проверочные данные аутентификации и ключ хранилища, зашифрованный
// на клиенте.
type User struct {
	ID              string
	Username        string
	AuthSalt        []byte
	KDF             protocol.KDFParameters
	AuthVerifier    []byte
	WrappedVaultKey []byte
	WrapNonce       []byte
	CreatedAt       time.Time
}

// Session описывает access/refresh bearer-токены, которые на сервере хранятся
// только в виде хэшей.
type Session struct {
	ID               string
	UserID           string
	AccessTokenHash  []byte
	RefreshTokenHash []byte
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	DeviceName       string
	RevokedAt        *time.Time
	CreatedAt        time.Time
}

// Repository задаёт контракт транзакционного хранилища для серверных сервисов.
// Реализации обязаны изолировать записи по идентификатору пользователя.
type Repository interface {
	CreateUser(context.Context, User) error
	UserByUsername(context.Context, string) (User, error)
	CreateSession(context.Context, Session) error
	SessionByAccessHash(context.Context, []byte) (Session, error)
	SessionByRefreshHash(context.Context, []byte) (Session, error)
	RevokeSession(context.Context, string, time.Time) error
	GetItem(context.Context, string, string) (protocol.EncryptedItem, error)
	PutItem(context.Context, string, string, int64, protocol.EncryptedItem, time.Time) (protocol.EncryptedItem, error)
	DeleteItem(context.Context, string, string, int64, time.Time) (protocol.EncryptedItem, error)
	Sync(context.Context, string, int64, int) (protocol.SyncResponse, error)
}
