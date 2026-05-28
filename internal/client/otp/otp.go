// Пакет otp разбирает и считает одноразовые TOTP-коды на стороне клиента,
// поэтому секретное значение не нужно раскрывать серверу.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"

	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
)

// ParseURI разбирает стандартный otpauth://totp URI в структуру OTP-секрета,
// которая затем хранится внутри зашифрованной записи.
func ParseURI(raw string) (vaultcrypto.OTPSecret, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		return vaultcrypto.OTPSecret{}, errors.New("invalid TOTP URI")
	}
	query := parsed.Query()
	secret := vaultcrypto.OTPSecret{
		Secret:    strings.ToUpper(strings.TrimSpace(query.Get("secret"))),
		Issuer:    query.Get("issuer"),
		Account:   strings.TrimPrefix(parsed.Path, "/"),
		Algorithm: strings.ToUpper(query.Get("algorithm")),
	}
	if secret.Secret == "" {
		return vaultcrypto.OTPSecret{}, errors.New("TOTP secret is required")
	}
	if secret.Algorithm == "" {
		secret.Algorithm = "SHA1"
	}
	secret.Digits = integerDefault(query.Get("digits"), 6)
	secret.Period = integerDefault(query.Get("period"), 30)
	if _, err := Generate(secret, time.Unix(0, 0)); err != nil {
		return vaultcrypto.OTPSecret{}, err
	}
	return secret, nil
}

// Generate рассчитывает TOTP-код для указанного секрета и момента времени по
// RFC 6238.
func Generate(config vaultcrypto.OTPSecret, now time.Time) (string, error) {
	period := config.Period
	if period == 0 {
		period = 30
	}
	digits := config.Digits
	if digits == 0 {
		digits = 6
	}
	if period <= 0 || (digits != 6 && digits != 8) {
		return "", errors.New("TOTP period or digits are invalid")
	}
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	seed, err := decoder.DecodeString(strings.ToUpper(strings.ReplaceAll(config.Secret, " ", "")))
	if err != nil || len(seed) == 0 {
		return "", errors.New("TOTP secret is not valid base32")
	}
	factory, err := hashFor(config.Algorithm)
	if err != nil {
		return "", err
	}
	counter := uint64(now.Unix() / int64(period))
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(factory, seed)
	mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

func integerDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}
	return value
}

func hashFor(name string) (func() hash.Hash, error) {
	switch strings.ToUpper(name) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported TOTP algorithm %q", name)
	}
}
