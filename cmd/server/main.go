// Команда server запускает HTTP API GophKeeper для регистрации, авторизации и
// синхронизации зашифрованного хранилища.
package main

import (
	"log"

	"github.com/ajgultumerkina/gophkeeper/internal/server/app"
)

func main() {
	app, err := app.InitializeApp()
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
