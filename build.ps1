# Compila dist\MiniWall.exe en Windows.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$version = if ($env:VERSION) { $env:VERSION } else { "1.0.0" }
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64 --out rsrc `
  --file-version "$version.0" --product-version "$version.0"
New-Item -ItemType Directory -Force dist | Out-Null
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$version" -o dist/MiniWall.exe .
Write-Host "Listo: dist\MiniWall.exe"
