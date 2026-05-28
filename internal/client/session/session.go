// Пакет session сохраняет локальный профиль клиента без мастер-пароля и без
// расшифрованного ключа хранилища.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
)

// Profile содержит адрес сервера, bearer-токены и зашифрованные данные для
// открытия хранилища на конкретном устройстве.
type Profile struct {
	Server string `json:"server"`
	protocol.LoginResponse
}

// DefaultPath возвращает стандартный путь к файлу активной сессии пользователя.
func DefaultPath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "gophkeeper", "session.json"), nil
}

// Save атомарно записывает профиль с правами доступа только для владельца.
func Save(path string, profile Profile) error {
	if path == "" {
		return errors.New("session path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".session-*")
	if err != nil {
		return fmt.Errorf("create temporary session: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if err := json.NewEncoder(temp).Encode(profile); err != nil {
		temp.Close()
		return fmt.Errorf("write session: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace session: %w", err)
	}
	return nil
}

// Load читает активный аутентифицированный профиль клиента.
func Load(path string) (Profile, error) {
	file, err := os.Open(path)
	if err != nil {
		return Profile{}, fmt.Errorf("load session: %w", err)
	}
	defer file.Close()
	var profile Profile
	if err := json.NewDecoder(file).Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("decode session: %w", err)
	}
	if profile.Server == "" || profile.AccessToken == "" || profile.Username == "" {
		return Profile{}, errors.New("session is incomplete; login again")
	}
	return profile, nil
}

// Delete удаляет локальный профиль сессии после выхода.
func Delete(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
