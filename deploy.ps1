# Despliega el sitio a Cloudflare Pages.
#
# Cloudflare Pages publica el contenido de _site, NO la raiz del repo. Si editas
# un HTML y despliegas sin copiarlo primero, el cambio no se ve y parece un
# problema de cache. Este script copia y despliega en un solo paso para que no
# pueda pasar.
#
#   .\deploy.ps1
#
# El Worker (worker/) se despliega aparte:  cd worker; npx wrangler deploy

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$ARCHIVOS = @(
  'index.html','cotizador.html','admin.html','api.js','site.webmanifest',
  'favicon.ico','favicon-16x16.png','favicon-32x32.png','favicon-48x48.png',
  'apple-touch-icon.png','android-chrome-192x192.png','android-chrome-512x512.png'
)

Write-Host "== Validando antes de publicar ==" -ForegroundColor Cyan
$errores = 0
foreach ($f in @('index.html','cotizador.html','admin.html')) {
  $c = Get-Content $f -Raw -Encoding UTF8
  $abre  = ([regex]::Matches($c, '<script')).Count
  $cierra = ([regex]::Matches($c, '</script>')).Count
  $body  = ([regex]::Matches($c, '</body>')).Count
  if ($abre -ne $cierra -or $body -ne 1) {
    Write-Host "  X $f : script $abre/$cierra, body $body" -ForegroundColor Red
    $errores++
  } else {
    Write-Host "  OK $f" -ForegroundColor Green
  }
}
if ($errores -gt 0) { Write-Host "`nAbortado: corrige los errores antes de publicar." -ForegroundColor Red; exit 1 }

Write-Host "`n== Preparando _site ==" -ForegroundColor Cyan
if (Test-Path _site) { Remove-Item _site -Recurse -Force }
New-Item -ItemType Directory -Path _site | Out-Null
$faltan = @()
foreach ($f in $ARCHIVOS) {
  if (Test-Path $f) { Copy-Item $f -Destination _site } else { $faltan += $f }
}
if ($faltan.Count -gt 0) { Write-Host "  Faltan: $($faltan -join ', ')" -ForegroundColor Yellow }
Write-Host "  $((Get-ChildItem _site).Count) archivos listos"

Write-Host "`n== Publicando en Cloudflare Pages ==" -ForegroundColor Cyan
npx wrangler pages deploy _site --project-name lunagi-cotizador --branch main --commit-dirty=true

Write-Host "`n== Comprobando que el sitio responde ==" -ForegroundColor Cyan
Start-Sleep -Seconds 4
foreach ($r in @('/', '/cotizador', '/admin')) {
  try {
    $resp = Invoke-WebRequest "https://lunagi-cotizador.pages.dev$r" -UseBasicParsing
    Write-Host ("  OK {0,-12} {1} KB" -f $r, [math]::Round($resp.Content.Length/1KB)) -ForegroundColor Green
  } catch {
    Write-Host "  X  $r no responde" -ForegroundColor Red
  }
}
Write-Host "`nListo: https://lunagi-cotizador.pages.dev" -ForegroundColor Cyan
