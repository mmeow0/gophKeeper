package logger

import (
	"errors"
	"log/slog"
	"testing"
)

func TestNewLoggerAcceptsKnownLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "fatal", ""} {
		if _, err := NewLogger(level); err != nil {
			t.Fatalf("NewLogger(%q) = %v", level, err)
		}
	}
}

func TestNewLoggerRejectsUnknownLevel(t *testing.T) {
	if _, err := NewLogger("verbose"); !errors.Is(err, ErrUnknownLevel) {
		t.Fatalf("NewLogger() error = %v", err)
	}
}

func TestSetDefaultUpdatesGlobalLogger(t *testing.T) {
	log := slog.Default()
	SetDefault(log)
	if Log != log {
		t.Fatal("глобальный логгер не был обновлён")
	}
}
