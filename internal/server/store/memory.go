package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

// Memory потокобезопасно хранит данные в памяти и используется для локального
// запуска и тестов. Это хранилище не сохраняет данные между перезапусками.
type Memory struct {
	mu        sync.RWMutex
	users     map[string]User
	usernames map[string]string
	sessions  map[string]Session
	access    map[string]string
	refresh   map[string]string
	items     map[string]map[string]protocol.EncryptedItem
	revisions map[string]int64
}

// NewMemory создаёт пустое хранилище в памяти.
func NewMemory() *Memory {
	return &Memory{
		users:     make(map[string]User),
		usernames: make(map[string]string),
		sessions:  make(map[string]Session),
		access:    make(map[string]string),
		refresh:   make(map[string]string),
		items:     make(map[string]map[string]protocol.EncryptedItem),
		revisions: make(map[string]int64),
	}
}

// CreateUser сохраняет аккаунт, если нормализованное имя пользователя ещё не
// занято.
func (m *Memory) CreateUser(_ context.Context, user User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.usernames[user.Username]; exists {
		return ErrAlreadyExists
	}
	user = cloneUser(user)
	m.users[user.ID] = user
	m.usernames[user.Username] = user.ID
	m.items[user.ID] = make(map[string]protocol.EncryptedItem)
	return nil
}

// UserByUsername ищет аккаунт по нормализованному имени пользователя.
func (m *Memory) UserByUsername(_ context.Context, username string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, exists := m.usernames[username]
	if !exists {
		return User{}, ErrNotFound
	}
	return cloneUser(m.users[id]), nil
}

// CreateSession сохраняет хэши bearer-токенов, не сохраняя сами токены.
func (m *Memory) CreateSession(_ context.Context, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = cloneSession(session)
	m.access[string(session.AccessTokenHash)] = session.ID
	m.refresh[string(session.RefreshTokenHash)] = session.ID
	return nil
}

// SessionByAccessHash находит сессию по хэшу access-токена.
func (m *Memory) SessionByAccessHash(_ context.Context, hash []byte) (Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.access[string(hash)]
	if !ok {
		return Session{}, ErrNotFound
	}
	return cloneSession(m.sessions[id]), nil
}

// SessionByRefreshHash находит сессию по хэшу refresh-токена.
func (m *Memory) SessionByRefreshHash(_ context.Context, hash []byte) (Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.refresh[string(hash)]
	if !ok {
		return Session{}, ErrNotFound
	}
	return cloneSession(m.sessions[id]), nil
}

// RevokeSession помечает сессию как отозванную.
func (m *Memory) RevokeSession(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	session.RevokedAt = &now
	m.sessions[id] = session
	return nil
}

// GetItem возвращает зашифрованную запись, принадлежащую пользователю.
func (m *Memory) GetItem(_ context.Context, userID, itemID string) (protocol.EncryptedItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.items[userID][itemID]
	if !ok {
		return protocol.EncryptedItem{}, ErrNotFound
	}
	return cloneItem(item), nil
}

// PutItem создаёт или заменяет зашифрованную запись, если BaseVersion совпадает
// с текущей версией.
func (m *Memory) PutItem(_ context.Context, userID, itemID string, baseVersion int64, incoming protocol.EncryptedItem, now time.Time) (protocol.EncryptedItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items, ok := m.items[userID]
	if !ok {
		return protocol.EncryptedItem{}, ErrNotFound
	}
	existing, exists := items[itemID]
	if (!exists && baseVersion != 0) || (exists && existing.Version != baseVersion) {
		return protocol.EncryptedItem{}, ErrConflict
	}
	m.revisions[userID]++
	incoming.ID = itemID
	incoming.Version = baseVersion + 1
	incoming.Revision = m.revisions[userID]
	incoming.UpdatedAt = now
	incoming.Deleted = false
	items[itemID] = cloneItem(incoming)
	return cloneItem(incoming), nil
}

// DeleteItem создаёт синхронизируемую метку удаления для существующей актуальной
// записи.
func (m *Memory) DeleteItem(_ context.Context, userID, itemID string, baseVersion int64, now time.Time) (protocol.EncryptedItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, exists := m.items[userID][itemID]
	if !exists || existing.Deleted {
		return protocol.EncryptedItem{}, ErrNotFound
	}
	if existing.Version != baseVersion {
		return protocol.EncryptedItem{}, ErrConflict
	}
	m.revisions[userID]++
	item := protocol.EncryptedItem{
		ID:        itemID,
		Version:   baseVersion + 1,
		Revision:  m.revisions[userID],
		Deleted:   true,
		UpdatedAt: now,
	}
	m.items[userID][itemID] = item
	return item, nil
}

// Sync возвращает изменения после монотонно растущей ревизии пользователя.
func (m *Memory) Sync(_ context.Context, userID string, after int64, limit int) (protocol.SyncResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items, ok := m.items[userID]
	if !ok {
		return protocol.SyncResponse{}, ErrNotFound
	}
	response := protocol.SyncResponse{CurrentRevision: m.revisions[userID]}
	for _, item := range items {
		if item.Revision > after {
			response.Items = append(response.Items, cloneItem(item))
		}
	}
	sort.Slice(response.Items, func(i, j int) bool { return response.Items[i].Revision < response.Items[j].Revision })
	if len(response.Items) > limit {
		response.Items = response.Items[:limit]
		response.CurrentRevision = response.Items[len(response.Items)-1].Revision
	}
	return response, nil
}

func cloneUser(user User) User {
	user.AuthSalt = append([]byte(nil), user.AuthSalt...)
	user.AuthVerifier = append([]byte(nil), user.AuthVerifier...)
	user.WrappedVaultKey = append([]byte(nil), user.WrappedVaultKey...)
	user.WrapNonce = append([]byte(nil), user.WrapNonce...)
	return user
}

func cloneSession(session Session) Session {
	session.AccessTokenHash = append([]byte(nil), session.AccessTokenHash...)
	session.RefreshTokenHash = append([]byte(nil), session.RefreshTokenHash...)
	return session
}

func cloneItem(item protocol.EncryptedItem) protocol.EncryptedItem {
	item.Nonce = append([]byte(nil), item.Nonce...)
	item.Ciphertext = append([]byte(nil), item.Ciphertext...)
	return item
}
