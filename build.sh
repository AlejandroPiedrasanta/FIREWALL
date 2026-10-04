#!/usr/bin/env sh
# Compila dist/MiniWall.exe (Windows x64) desde cualquier sistema con Go.
set -e
cd "$(dirname "$0")"
VERSION="${VERSION:-1.0.0}"
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64 --out rsrc \
  --file-version "$VERSION.0" --product-version "$VERSION.0"
mkdir -p dist
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o dist/MiniWall.exe .
echo "Listo: dist/MiniWall.exe"
