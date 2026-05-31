// Пакет vaultcrypto отвечает за клиентский вывод ключей и аутентифицированное
// шифрование записей GophKeeper.
package vaultcrypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// CryptoVersion обозначает версию формата зашифрованной записи.
	CryptoVersion = 1
	keySize       = chacha20poly1305.KeySize
	saltSize      = 16
)

// Kind задаёт тип открытого секрета, который лежит внутри зашифрованной записи.
type Kind string

const (
	// KindLogin хранит пару логин/пароль.
	KindLogin Kind = "login"
	// KindText хранит произвольный текст.
	KindText Kind = "text"
	// KindBinary хранит произвольное содержимое файла.
	KindBinary Kind = "binary"
	// KindCard хранит данные банковской карты.
	KindCard Kind = "card"
	// KindOTP хранит секрет TOTP и параметры отображения кода.
	KindOTP Kind = "otp"
)

// Secret описывает открытое содержимое записи, которое существует только на
// клиенте после расшифровки.
type Secret struct {
	ID       string        `json:"id"`
	Kind     Kind          `json:"kind"`
	Name     string        `json:"name"`
	Metadata string        `json:"metadata,omitempty"`
	Login    *LoginSecret  `json:"login,omitempty"`
	Text     *TextSecret   `json:"text,omitempty"`
	Binary   *BinarySecret `json:"binary,omitempty"`
	Card     *CardSecret   `json:"card,omitempty"`
	OTP      *OTPSecret    `json:"otp,omitempty"`
}

// LoginSecret содержит учётные данные для сайта или приложения.
type LoginSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TextSecret содержит произвольный чувствительный текст.
type TextSecret struct {
	Value string `json:"value"`
}

// BinarySecret содержит чувствительный файл или набор байтов.
type BinarySecret struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type,omitempty"`
	Data     []byte `json:"data"`
}

// CardSecret содержит данные банковской карты.
type CardSecret struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"`
	CVV    string `json:"cvv"`
}

// OTPSecret содержит настройки, необходимые для локального расчёта TOTP-кодов.
type OTPSecret struct {
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer,omitempty"`
	Account   string `json:"account,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
}

// VaultSetup объединяет криптографические данные, которые клиент создаёт при
// регистрации.
type VaultSetup struct {
	AuthSalt        []byte
	KDF             protocol.KDFParameters
	AuthKey         []byte
	VaultKey        []byte
	WrappedVaultKey []byte
	WrapNonce       []byte
}

// DefaultKDFParameters возвращает рабочие параметры Argon2id для обычного
// использования приложения.
func DefaultKDFParameters() protocol.KDFParameters {
	return protocol.KDFParameters{
		Time:        3,
		Memory:      64 * 1024,
		Parallelism: 2,
		KeyLength:   keySize,
	}
}

// NewVaultSetup создаёт случайный ключ хранилища и заворачивает его ключом,
// выведенным из мастер-пароля пользователя. Имя пользователя нормализуется так
// же, как на сервере.
func NewVaultSetup(username, password string, params protocol.KDFParameters) (VaultSetup, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	salt, err := randomBytes(saltSize)
	if err != nil {
		return VaultSetup{}, fmt.Errorf("generate auth salt: %w", err)
	}
	authKey, wrapKey, err := DeriveKeys(password, salt, params)
	if err != nil {
		return VaultSetup{}, err
	}
	vaultKey, err := randomBytes(keySize)
	if err != nil {
		return VaultSetup{}, fmt.Errorf("generate vault key: %w", err)
	}
	wrapped, nonce, err := WrapVaultKey(vaultKey, wrapKey, username)
	if err != nil {
		return VaultSetup{}, err
	}
	return VaultSetup{
		AuthSalt:        salt,
		KDF:             params,
		AuthKey:         authKey,
		VaultKey:        vaultKey,
		WrappedVaultKey: wrapped,
		WrapNonce:       nonce,
	}, nil
}

// DeriveKeys выводит из мастер-пароля отдельные ключи для аутентификации и для
// оборачивания ключа хранилища. Разделение доменов сделано через HMAC-метки.
func DeriveKeys(password string, salt []byte, params protocol.KDFParameters) ([]byte, []byte, error) {
	if err := validateKDF(params); err != nil {
		return nil, nil, err
	}
	if len(salt) < saltSize {
		return nil, nil, errors.New("authentication salt is too short")
	}
	root := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Parallelism, params.KeyLength)
	authKey := expandKey(root, []byte("gophkeeper/auth/v1"))
	wrapKey := expandKey(root, []byte("gophkeeper/vault-wrap/v1"))
	return authKey, wrapKey, nil
}

// WrapVaultKey шифрует ключ хранилища ключом, который был выведен из
// мастер-пароля.
func WrapVaultKey(vaultKey, wrapKey []byte, username string) ([]byte, []byte, error) {
	if len(vaultKey) != keySize || len(wrapKey) != keySize {
		return nil, nil, errors.New("invalid vault or wrapping key length")
	}
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create vault wrapper: %w", err)
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, fmt.Errorf("generate wrap nonce: %w", err)
	}
	return aead.Seal(nil, nonce, vaultKey, []byte(username)), nonce, nil
}

// UnwrapVaultKey восстанавливает ключ хранилища после того, как пользователь
// локально ввёл правильный мастер-пароль.
func UnwrapVaultKey(wrapped, nonce, wrapKey []byte, username string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("create vault wrapper: %w", err)
	}
	key, err := aead.Open(nil, nonce, wrapped, []byte(username))
	if err != nil {
		return nil, errors.New("invalid master password or corrupted vault key")
	}
	if len(key) != keySize {
		return nil, errors.New("unwrapped vault key has invalid length")
	}
	return key, nil
}

// EncryptSecret сериализует и шифрует открытый секрет перед отправкой и
// хранением на сервере.
func EncryptSecret(vaultKey []byte, secret Secret) (protocol.EncryptedItem, error) {
	if secret.ID == "" {
		return protocol.EncryptedItem{}, errors.New("secret ID is required")
	}
	if err := ValidateSecret(secret); err != nil {
		return protocol.EncryptedItem{}, err
	}
	plain, err := json.Marshal(secret)
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("serialize secret: %w", err)
	}
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("create record cipher: %w", err)
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("generate record nonce: %w", err)
	}
	return protocol.EncryptedItem{
		ID:            secret.ID,
		CryptoVersion: CryptoVersion,
		Nonce:         nonce,
		Ciphertext:    aead.Seal(nil, nonce, plain, []byte(secret.ID)),
	}, nil
}

// DecryptSecret проверяет подлинность серверного конверта и расшифровывает его
// локально на клиенте.
func DecryptSecret(vaultKey []byte, encrypted protocol.EncryptedItem) (Secret, error) {
	if encrypted.CryptoVersion != CryptoVersion {
		return Secret{}, fmt.Errorf("unsupported crypto version %d", encrypted.CryptoVersion)
	}
	aead, err := chacha20poly1305.NewX(vaultKey)
	if err != nil {
		return Secret{}, fmt.Errorf("create record cipher: %w", err)
	}
	plain, err := aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, []byte(encrypted.ID))
	if err != nil {
		return Secret{}, errors.New("record authentication failed")
	}
	var secret Secret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return Secret{}, fmt.Errorf("decode secret: %w", err)
	}
	if secret.ID != encrypted.ID {
		return Secret{}, errors.New("record ID does not match envelope")
	}
	if err := ValidateSecret(secret); err != nil {
		return Secret{}, err
	}
	return secret, nil
}

// ValidateSecret проверяет, что открытый секрет содержит обязательные данные
// для выбранного типа записи.
func ValidateSecret(secret Secret) error {
	if secret.ID == "" || secret.Name == "" {
		return errors.New("secret ID and name are required")
	}
	var valid bool
	switch secret.Kind {
	case KindLogin:
		valid = secret.Login != nil && secret.Login.Password != ""
	case KindText:
		valid = secret.Text != nil
	case KindBinary:
		valid = secret.Binary != nil
	case KindCard:
		valid = secret.Card != nil && secret.Card.Number != ""
	case KindOTP:
		valid = secret.OTP != nil && secret.OTP.Secret != ""
	default:
		return fmt.Errorf("unknown secret kind %q", secret.Kind)
	}
	if !valid {
		return fmt.Errorf("missing payload for secret kind %q", secret.Kind)
	}
	return nil
}

// NewID возвращает криптографически случайный идентификатор для записей и
// серверных сущностей.
func NewID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validateKDF(params protocol.KDFParameters) error {
	if params.Time < 1 || params.Time > 10 ||
		params.Memory < 8*1024 || params.Memory > 1024*1024 ||
		params.Parallelism < 1 || params.Parallelism > 16 ||
		params.KeyLength != keySize {
		return errors.New("invalid Argon2id parameters")
	}
	return nil
}

func expandKey(root, label []byte) []byte {
	mac := hmac.New(sha256.New, root)
	mac.Write(label)
	return mac.Sum(nil)
}

func randomBytes(length int) ([]byte, error) {
	value := make([]byte, length)
	_, err := rand.Read(value)
	return value, err
}
