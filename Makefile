VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS = -X github.com/ajgultumerkina/gophkeeper/internal/buildinfo.version=$(VERSION) \
	-X github.com/ajgultumerkina/gophkeeper/internal/buildinfo.date=$(BUILD_DATE) \
	-X github.com/ajgultumerkina/gophkeeper/internal/buildinfo.commit=$(COMMIT)

.PHONY: test coverage vet build build-client-all server

test:
	go test -race ./...

coverage:
	go test -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -o bin/server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper ./cmd/gophkeeper

build-client-all:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-linux-amd64 ./cmd/gophkeeper
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-darwin-amd64 ./cmd/gophkeeper
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-darwin-arm64 ./cmd/gophkeeper
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-windows-amd64.exe ./cmd/gophkeeper

server:
	go run ./cmd/server -memory

