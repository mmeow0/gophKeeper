// Пакет protocol описывает структуры JSON API, общие для CLI-клиента и
// сервера GophKeeper.
package protocol

import "time"

// KDFParameters хранит параметры Argon2id, выбранные при регистрации
// пользователя.
type KDFParameters struct {
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"key_length"`
}

// RegisterRequest передаёт серверу данные для создания пользователя и
// зашифрованный на клиенте ключ хранилища.
type RegisterRequest struct {
	Username        string        `json:"username"`
	AuthSalt        []byte        `json:"auth_salt"`
	KDF             KDFParameters `json:"kdf"`
	AuthKey         []byte        `json:"auth_key"`
	WrappedVaultKey []byte        `json:"wrapped_vault_key"`
	WrapNonce       []byte        `json:"wrap_nonce"`
}

// LoginParametersRequest запрашивает параметры вывода ключей перед тем, как
// клиент отправит производный ключ аутентификации.
type LoginParametersRequest struct {
	Username string `json:"username"`
}

// LoginParametersResponse позволяет клиенту вывести ключи локально, не передавая
// мастер-пароль на сервер.
type LoginParametersResponse struct {
	AuthSalt []byte        `json:"auth_salt"`
	KDF      KDFParameters `json:"kdf"`
}

// LoginRequest аутентифицирует клиента ключом, выведенным из мастер-пароля, и
// при необходимости подписывает устройство в создаваемой сессии.
type LoginRequest struct {
	Username   string `json:"username"`
	AuthKey    []byte `json:"auth_key"`
	DeviceName string `json:"device_name,omitempty"`
}

// TokenPair содержит bearer-токены, выданные успешно аутентифицированному
// клиенту.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// LoginResponse возвращает новую сессию и зашифрованный ключ хранилища, который
// можно открыть только локально выведенным ключом оборачивания.
type LoginResponse struct {
	TokenPair
	Username        string        `json:"username"`
	AuthSalt        []byte        `json:"auth_salt"`
	KDF             KDFParameters `json:"kdf"`
	WrappedVaultKey []byte        `json:"wrapped_vault_key"`
	WrapNonce       []byte        `json:"wrap_nonce"`
}

// RefreshRequest запрашивает замену refresh-токена на новую пару токенов.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// EncryptedItem представляет сохранённый на сервере зашифрованный конверт;
// открытый текст известен только клиенту с ключом хранилища.
type EncryptedItem struct {
	ID            string    `json:"id"`
	Version       int64     `json:"version"`
	Revision      int64     `json:"revision"`
	CryptoVersion int       `json:"crypto_version"`
	Nonce         []byte    `json:"nonce"`
	Ciphertext    []byte    `json:"ciphertext"`
	Deleted       bool      `json:"deleted"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// PutItemRequest создаёт или заменяет запись с проверкой BaseVersion, чтобы
// параллельные клиенты не перетирали изменения молча.
type PutItemRequest struct {
	BaseVersion   int64  `json:"base_version"`
	CryptoVersion int    `json:"crypto_version"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
}

// DeleteItemRequest создаёт метку удаления для записи с ожидаемой текущей
// версией.
type DeleteItemRequest struct {
	BaseVersion int64 `json:"base_version"`
}

// SyncResponse отдаёт изменения после клиентской ревизии и новый курсор
// синхронизации.
type SyncResponse struct {
	Items           []EncryptedItem `json:"items"`
	CurrentRevision int64           `json:"current_revision"`
}

// ErrorResponse задаёт стабильный JSON-формат ошибки API.
type ErrorResponse struct {
	Error string `json:"error"`
}
