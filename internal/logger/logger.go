// Пакет logger создаёт общий логгер приложения и настраивает стандартный slog.
package logger

import (
	"errors"
	"log/slog"
	"os"
	"strings"
)

// ErrUnknownLevel означает, что в конфигурации указан неподдерживаемый уровень
// логирования.
var ErrUnknownLevel = errors.New("unknown log level")

// Log хранит глобальный логгер приложения. По умолчанию используется INFO.
var Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

// NewLogger создаёт текстовый slog-логгер с уровнем из конфигурации.
func NewLogger(level string) (*slog.Logger, error) {
	parsed, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parsed})), nil
}

// SetDefault сохраняет логгер как глобальный и передаёт его в slog.SetDefault.
func SetDefault(log *slog.Logger) {
	if log == nil {
		log = Log
	}
	Log = log
	slog.SetDefault(log)
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "fatal":
		return slog.LevelError, nil
	default:
		return 0, ErrUnknownLevel
	}
}
