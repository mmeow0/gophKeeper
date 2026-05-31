// Пакет app собирает CLI-приложение GophKeeper и прячет техническую
// инициализацию от cmd/main.
package app

import (
	"context"
	"fmt"
	"os"

	"github.com/ajgultumerkina/gophkeeper/internal/client/command"
	"golang.org/x/term"
)

// App хранит готовый CLI-обработчик и аргументы текущего запуска.
type App struct {
	command *command.App
	args    []string
}

// InitializeApp подготавливает CLI: настраивает безопасное чтение паролей и
// запоминает аргументы командной строки.
func InitializeApp() (*App, error) {
	args := os.Args[1:]
	return &App{
		command: command.New(os.Stdin, os.Stdout, os.Stderr, readPassword, ""),
		args:    args,
	}, nil
}

// Run выполняет выбранную пользователем CLI-команду.
func (a *App) Run() error {
	return a.command.Run(context.Background(), a.args)
}

// Close оставлен для единого жизненного цикла приложений; CLI не держит
// долгоживущих ресурсов.
func (a *App) Close() {}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(value), err
}
