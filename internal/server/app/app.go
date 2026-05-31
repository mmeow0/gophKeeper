// Пакет app собирает серверное приложение из конфигурации, хранилища и HTTP API.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/logger"
	"github.com/ajgultumerkina/gophkeeper/internal/server/auth"
	"github.com/ajgultumerkina/gophkeeper/internal/server/config"
	"github.com/ajgultumerkina/gophkeeper/internal/server/httpapi"
	"github.com/ajgultumerkina/gophkeeper/internal/server/store"
	"github.com/ajgultumerkina/gophkeeper/internal/server/vault"
)

// App хранит все ресурсы серверного процесса и отвечает за их корректное
// закрытие.
type App struct {
	cfg             *config.Config
	logger          *slog.Logger
	server          *http.Server
	closeRepository func()
	stopped         chan os.Signal
}

// InitializeApp читает флаги и переменные окружения, подключает хранилище и
// собирает HTTP-сервер.
func InitializeApp() (*App, error) {
	cfg, err := config.NewConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	log, err := logger.NewLogger(cfg.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.SetDefault(log)

	repository, closeRepository, err := repository(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	pepper, generated, err := serverPepper(cfg)
	if err != nil {
		closeRepository()
		return nil, fmt.Errorf("failed to initialize authentication secret: %w", err)
	}
	if generated {
		log.Warn("using ephemeral authentication pepper in memory mode")
	}
	if cfg.MemoryStorage {
		log.Info("using memory storage")
	} else {
		log.Info("using PostgreSQL storage", slog.String("dsn", maskDSN(cfg.DatabaseURL)))
	}

	handler := httpapi.New(auth.NewService(repository, pepper), vault.NewService(repository))
	server := &http.Server{
		Addr:              cfg.RunAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	return &App{
		cfg:             cfg,
		logger:          log,
		server:          server,
		closeRepository: closeRepository,
		stopped:         make(chan os.Signal, 1),
	}, nil
}

// Run запускает HTTP-сервер и обрабатывает штатное завершение по сигналу ОС.
func (a *App) Run() error {
	signal.Notify(a.stopped, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-a.stopped
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.server.Shutdown(ctx)
	}()

	a.logger.Info("GophKeeper server listening", "address", a.server.Addr, "memory", a.cfg.MemoryStorage, "tls", a.cfg.TLSCertFile != "")
	var err error
	if a.cfg.TLSCertFile != "" {
		err = a.server.ListenAndServeTLS(a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
	} else {
		err = a.server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close освобождает ресурсы, которыми владеет приложение.
func (a *App) Close() {
	if a == nil {
		return
	}
	if a.stopped != nil {
		signal.Stop(a.stopped)
	}
	if a.closeRepository != nil {
		a.closeRepository()
	}
}

func repository(ctx context.Context, cfg *config.Config) (store.Repository, func(), error) {
	if cfg.MemoryStorage {
		return store.NewMemory(), func() {}, nil
	}
	postgres, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return postgres, func() { _ = postgres.Close() }, nil
}

func serverPepper(cfg *config.Config) ([]byte, bool, error) {
	if cfg.Pepper != "" {
		return []byte(cfg.Pepper), false, nil
	}
	if !cfg.MemoryStorage {
		return nil, false, config.ErrEmptyPepper
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, false, fmt.Errorf("generate development pepper: %w", err)
	}
	return value, true, nil
}

func maskDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "***"
	}
	if parsed.User != nil {
		parsed.User = url.UserPassword(parsed.User.Username(), "***")
	}
	return parsed.String()
}
