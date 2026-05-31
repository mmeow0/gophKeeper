// Пакет vault реализует серверную бизнес-логику хранения и синхронизации
// зашифрованных записей.
package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
)

// ErrInvalidInput означает некорректную операцию с зашифрованной записью.
var ErrInvalidInput = errors.New("invalid input")

// Service работает только с непрозрачными зашифрованными конвертами и не умеет
// расшифровывать пользовательские секреты.
type Service struct {
	repository store.Repository
	now        func() time.Time
}

// NewService создаёт сервис зашифрованного хранилища.
func NewService(repository store.Repository) *Service {
	return &Service{repository: repository, now: time.Now}
}

// Get возвращает одну активную зашифрованную запись её владельцу.
func (s *Service) Get(ctx context.Context, userID, itemID string) (protocol.EncryptedItem, error) {
	item, err := s.repository.GetItem(ctx, userID, itemID)
	if err != nil {
		return protocol.EncryptedItem{}, err
	}
	if item.Deleted {
		return protocol.EncryptedItem{}, store.ErrNotFound
	}
	return item, nil
}

// Put сохраняет зашифрованную запись после проверки размера и формата
// криптографического конверта.
func (s *Service) Put(ctx context.Context, userID, itemID string, request protocol.PutItemRequest) (protocol.EncryptedItem, error) {
	if itemID == "" || request.CryptoVersion != 1 || len(request.Nonce) != 24 || len(request.Ciphertext) == 0 {
		return protocol.EncryptedItem{}, fmt.Errorf("%w: invalid encrypted item envelope", ErrInvalidInput)
	}
	if len(request.Ciphertext) > 16<<20 {
		return protocol.EncryptedItem{}, fmt.Errorf("%w: encrypted item exceeds 16 MiB limit", ErrInvalidInput)
	}
	return s.repository.PutItem(ctx, userID, itemID, request.BaseVersion, protocol.EncryptedItem{
		ID:            itemID,
		CryptoVersion: request.CryptoVersion,
		Nonce:         request.Nonce,
		Ciphertext:    request.Ciphertext,
	}, s.now().UTC())
}

// Delete записывает метку удаления, чтобы все синхронизированные клиенты узнали
// об удалении записи.
func (s *Service) Delete(ctx context.Context, userID, itemID string, request protocol.DeleteItemRequest) (protocol.EncryptedItem, error) {
	if itemID == "" || request.BaseVersion < 1 {
		return protocol.EncryptedItem{}, fmt.Errorf("%w: invalid delete request", ErrInvalidInput)
	}
	return s.repository.DeleteItem(ctx, userID, itemID, request.BaseVersion, s.now().UTC())
}

// Sync возвращает изменения после последней ревизии, которую клиент уже
// обработал.
func (s *Service) Sync(ctx context.Context, userID string, after int64, limit int) (protocol.SyncResponse, error) {
	if after < 0 {
		return protocol.SyncResponse{}, fmt.Errorf("%w: revision cannot be negative", ErrInvalidInput)
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 500 {
		return protocol.SyncResponse{}, fmt.Errorf("%w: sync limit must be between 1 and 500", ErrInvalidInput)
	}
	return s.repository.Sync(ctx, userID, after, limit)
}
