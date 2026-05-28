// Пакет buildinfo хранит сведения о сборке клиента, которые подставляются через
// флаги компоновщика при релизной сборке.
package buildinfo

import "fmt"

var (
	version = "dev"
	date    = "unknown"
	commit  = "unknown"
)

// Set переопределяет сведения о сборке; это удобно в тестах и при нестандартной
// сборке бинарного файла.
func Set(newVersion, newDate, newCommit string) {
	version, date, commit = newVersion, newDate, newCommit
}

// String форматирует версию клиента и данные о происхождении сборки для вывода
// в терминал.
func String() string {
	return fmt.Sprintf("GophKeeper %s (built %s, commit %s)", version, date, commit)
}
