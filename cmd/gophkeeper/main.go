// Команда gophkeeper запускает кроссплатформенный CLI-клиент для личных
// зашифрованных секретов, которые синхронизируются через сервер GophKeeper.
package main

import (
	"log"

	"github.com/ajgultumerkina/gophkeeper/internal/client/app"
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
