// Пакет config читает настройки серверного приложения из флагов и переменных
// окружения.
package config

import (
	"errors"
	"flag"
	"os"
	"strconv"
	"strings"
)

var (
	// ErrEmptyRunAddress означает, что адрес запуска HTTP API не задан.
	ErrEmptyRunAddress = errors.New("server address is empty")
	// ErrEmptyDatabaseURL означает, что для постоянного режима не задана база.
	ErrEmptyDatabaseURL = errors.New("database URL is required unless memory storage is selected")
	// ErrEmptyPepper означает, что для постоянного режима не задан серверный pepper.
	ErrEmptyPepper = errors.New("pepper is required unless memory storage is selected")
	// ErrIncompleteTLS означает, что указан только сертификат или только ключ TLS.
	ErrIncompleteTLS = errors.New("both TLS certificate and key are required together")
)

// Config хранит все настройки, необходимые для сборки серверного приложения.
type Config struct {
	// Адрес и порт запуска HTTP API.
	RunAddress string

	// Строка подключения к PostgreSQL.
	DatabaseURL string

	// Признак запуска с временным хранилищем в памяти.
	MemoryStorage bool

	// Путь к TLS-сертификату сервера.
	TLSCertFile string

	// Путь к приватному TLS-ключу сервера.
	TLSKeyFile string

	// Уровень логирования: debug, info, warn, error или fatal.
	LogLevel string

	// Серверный pepper для HMAC-проверки ключей аутентификации.
	Pepper string
}

// NewConfig читает конфигурацию из os.Args и переменных окружения.
func NewConfig() (*Config, error) {
	return NewConfigFromArgs(os.Args[1:])
}

// NewConfigFromArgs читает конфигурацию из переданного списка аргументов. Эта
// функция нужна тестам, чтобы не менять глобальный flag.CommandLine.
func NewConfigFromArgs(args []string) (*Config, error) {
	cfg := &Config{
		RunAddress:    envDefault("GOPHKEEPER_LISTEN", ":8080"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		MemoryStorage: envBool("GOPHKEEPER_MEMORY", false),
		TLSCertFile:   os.Getenv("GOPHKEEPER_TLS_CERT"),
		TLSKeyFile:    os.Getenv("GOPHKEEPER_TLS_KEY"),
		LogLevel:      envDefault("GOPHKEEPER_LOG_LEVEL", "info"),
		Pepper:        os.Getenv("GOPHKEEPER_PEPPER"),
	}

	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.StringVar(&cfg.RunAddress, "listen", cfg.RunAddress, "HTTP listen address")
	flags.StringVar(&cfg.DatabaseURL, "dsn", cfg.DatabaseURL, "PostgreSQL connection string")
	flags.BoolVar(&cfg.MemoryStorage, "memory", cfg.MemoryStorage, "use volatile in-memory storage for development")
	flags.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "TLS certificate file")
	flags.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "TLS private key file")
	flags.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate проверяет обязательные настройки и согласованность TLS-пары.
func (cfg *Config) Validate() error {
	if strings.TrimSpace(cfg.RunAddress) == "" {
		return ErrEmptyRunAddress
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return ErrIncompleteTLS
	}
	if !cfg.MemoryStorage && strings.TrimSpace(cfg.DatabaseURL) == "" {
		return ErrEmptyDatabaseURL
	}
	if !cfg.MemoryStorage && cfg.Pepper == "" {
		return ErrEmptyPepper
	}
	return nil
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}
