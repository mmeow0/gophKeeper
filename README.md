# GophKeeper

GophKeeper - клиент-серверный менеджер секретов на Go. CLI-клиент хранит и
расшифровывает логины, тексты, файлы, банковские карты и TOTP. Сервер
аутентифицирует пользователей и синхронизирует только зашифрованные записи.

## Возможности

- регистрация, login, refresh/logout сессий;
- клиентское шифрование `XChaCha20-Poly1305`;
- получение ключей из мастер-пароля через `Argon2id`;
- CRUD зашифрованных секретов и revision-based синхронизация;
- разрешение конкурирующих изменений через `409 Conflict`;
- TOTP по RFC 6238 и импорт `otpauth://totp/...`;
- PostgreSQL-хранилище и временный `-memory` режим;
- OpenAPI-описание в [`api/openapi.yaml`](api/openapi.yaml);
- CLI под Windows, Linux и macOS с версией и датой сборки.

## Безопасность

Мастер-пароль и открытый текст секретов не передаются серверу. При регистрации
клиент генерирует случайный `vaultKey`, выводит отдельные `authKey` и
`wrapKey` из мастер-пароля и сохраняет на сервере только verifier и
зашифрованный `vaultKey`. Каждая запись зашифрована локально с отдельным
nonce; её ID используется как authenticated associated data.

Сервер хранит bearer-токены только в виде SHA-256 хэшей. Клиентская сессия
содержит токены и обёрнутый ключ vault в файле с правами `0600`, но никогда не
содержит мастер-пароль или расшифрованный ключ.

Для удалённого сервера клиент принимает только `https://` URL. `http://`
разрешён для `localhost` при разработке. Сервер можно запускать с собственным
TLS-сертификатом либо за TLS reverse proxy.

## Быстрый Запуск

Тестовый сервер без постоянной базы:

```bash
export GOPHKEEPER_PEPPER='development-pepper-change-me'
go run ./cmd/server -memory
```

Во втором терминале:

```bash
go run ./cmd/gophkeeper register --server http://localhost:8080 --user alice
go run ./cmd/gophkeeper login --server http://localhost:8080 --user alice --device laptop
go run ./cmd/gophkeeper add login --name GitHub --meta personal
go run ./cmd/gophkeeper list
go run ./cmd/gophkeeper get ITEM_ID
```

Мастер-пароль, password записи, данные карты, текст секрета и OTP URI
считываются без эхо в терминале. Параметры `--name` и `--meta` видны в истории
shell: чувствительную метаинформацию не следует передавать ими на общей
машине.

## PostgreSQL

```bash
docker compose up -d postgres
export DATABASE_URL='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable'
export GOPHKEEPER_PEPPER='replace-with-a-long-random-server-secret'
go run ./cmd/server
```

Compose автоматически применяет [`migrations/001_init.sql`](migrations/001_init.sql)
при создании нового volume. Для уже существующей базы миграцию следует
применить отдельно перед запуском новой версии сервера.

## Команды Клиента

```text
gophkeeper register --server URL --user USER
gophkeeper login --server URL --user USER [--device NAME]
gophkeeper add login|text|card|binary|otp --name NAME [--meta TEXT] [--file PATH]
gophkeeper list | sync
gophkeeper get [--out PATH] ID
gophkeeper edit --name NAME [--meta TEXT] ID
gophkeeper delete ID
gophkeeper otp code ID
gophkeeper refresh | logout
gophkeeper version
```

`edit` изменяет имя и метаинформацию записи с optimistic locking. Бинарный
секрет извлекается только с `get --out PATH ID`, создавая файл с правами `0600`.
Размер ciphertext одной записи ограничен 16 MiB.

## Сборка

```bash
make build VERSION=1.0.0
./bin/gophkeeper version
make build-client-all VERSION=1.0.0
```

При release-сборке `Makefile` встраивает версию, UTC-дату и git commit через
`-ldflags`.

## Тестирование

```bash
make test
make vet
make coverage
```

Покрытие измеряется по всему модулю командой с `-coverpkg=./...`; текущий
набор unit- и integration-тестов покрывает криптографию, TOTP, CLI-поток,
HTTP auth/vault/sync и SQL-репозиторий.

## Структура

```text
cmd/server                 серверный бинарник
cmd/gophkeeper             CLI-клиент
internal/client            crypto, OTP, API, session, commands
internal/server            auth, vault, HTTP API, memory/PostgreSQL stores
internal/protocol          общий JSON API-контракт
api/openapi.yaml           OpenAPI 3 спецификация
migrations                 PostgreSQL schema
```

Подробности протокола и принятых решений приведены в
[`docs/architecture.md`](docs/architecture.md).
