# Staging Shield — Makefile
# Las dependencias están vendoreadas en ./vendor para builds offline.

BINARY := staging-shield
GO     := go

.PHONY: build build-all test vet clean install help

help:
	@echo "Targets disponibles:"
	@echo "  build        Compila el binario para la plataforma actual"
	@echo "  build-all    Compila para linux/macOS/windows en dist/"
	@echo "  vet          Ejecuta go vet sobre todos los paquetes"
	@echo "  test         Ejecuta tests (cuando existan)"
	@echo "  install      Instala el binario en \$$GOPATH/bin"
	@echo "  clean        Borra binarios generados"

build:
	$(GO) build -mod=vendor -o $(BINARY) .

build-all:
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 $(GO) build -mod=vendor -o dist/$(BINARY)-linux-amd64 .
	GOOS=darwin  GOARCH=amd64 $(GO) build -mod=vendor -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 $(GO) build -mod=vendor -o dist/$(BINARY)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GO) build -mod=vendor -o dist/$(BINARY)-windows-amd64.exe .

vet:
	$(GO) vet -mod=vendor ./...

test:
	$(GO) test -mod=vendor ./...

install:
	$(GO) install -mod=vendor .

clean:
	rm -f $(BINARY) /tmp/$(BINARY) /tmp/$(BINARY)2
	rm -rf dist
