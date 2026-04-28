#!/usr/bin/env bash
# Helper de build para entornos sin red. Usa el directorio vendor/
set -e
cd "$(dirname "$0")"
go build -mod=vendor -o staging-shield .
echo "✓ Binario creado: $(pwd)/staging-shield"
