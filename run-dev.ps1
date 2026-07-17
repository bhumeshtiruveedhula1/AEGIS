<#
.SYNOPSIS
  AEGIS Local Dev — starts backend + frontend in one command.

.USAGE
  cd C:\Users\bhumeshjyothi\Desktop\cyber-et\cybershield
  ..\run-dev.ps1

  Or from anywhere:
  & "C:\Users\bhumeshjyothi\Desktop\cyber-et\run-dev.ps1"

.NOTES
  Stops both processes cleanly on Ctrl+C.
  Not the demo script — dev only.
#>

$ROOT      = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKEND   = Join-Path $ROOT "cybershield"
$FRONTEND  = Join-Path $ROOT "frontend-team"
$VENV_PY   = Join-Path $BACKEND ".venv\Scripts\python.exe"
$HEALTH_URL = "http://127.0.0.1:8000/health"
$DASH_URL   = "http://localhost:3000/dashboard.html"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   AEGIS  —  Local Dev Runner          ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── 1. Start backend ────────────────────────────────────────────────────────
Write-Host "  [1/3] Starting backend (uvicorn :8000)..." -ForegroundColor Yellow
$backendProc = Start-Process -FilePath "cmd.exe" `
  -ArgumentList "/c", "set PYTHONIOENCODING=utf-8 && `"$VENV_PY`" -m uvicorn backend.api.app:create_app --factory --host 127.0.0.1 --port 8000" `
  -WorkingDirectory $BACKEND `
  -PassThru `
  -WindowStyle Normal

# ── 2. Poll health until ready (max 20 s) ───────────────────────────────────
Write-Host "  [2/3] Waiting for backend health check..." -ForegroundColor Yellow
$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-RestMethod -Uri $HEALTH_URL -TimeoutSec 2 -ErrorAction Stop
        if ($r.status) { $ready = $true; break }
    } catch { }
    Write-Host "       ... ($($i+1)s)" -ForegroundColor DarkGray
}

if (-not $ready) {
    Write-Host "  [!] Backend did not become healthy in 20s — check for errors above." -ForegroundColor Red
    Write-Host "      Continuing anyway (frontend may show fixture fallback data)." -ForegroundColor DarkGray
} else {
    Write-Host "  ✓  Backend healthy." -ForegroundColor Green
}

# ── 3. Start frontend ────────────────────────────────────────────────────────
Write-Host "  [3/3] Starting frontend (npm run dev :3000)..." -ForegroundColor Yellow
$frontendProc = Start-Process -FilePath "cmd.exe" `
  -ArgumentList "/c", "npm run dev" `
  -WorkingDirectory $FRONTEND `
  -PassThru `
  -WindowStyle Normal

Start-Sleep -Seconds 3   # give Vite a moment to bind

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Dashboard  →  $DASH_URL  │" -ForegroundColor Green
Write-Host "  │  Backend    →  http://localhost:8000         │" -ForegroundColor Green
Write-Host "  │  API docs   →  http://localhost:8000/docs    │" -ForegroundColor Green
Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop both processes." -ForegroundColor DarkGray
Write-Host ""

# ── Keep alive — clean shutdown on Ctrl+C ───────────────────────────────────
try {
    while ($true) { Start-Sleep -Seconds 5 }
} finally {
    Write-Host "`n  Stopping processes..." -ForegroundColor Yellow
    if ($backendProc  -and -not $backendProc.HasExited)  { Stop-Process -Id $backendProc.Id  -Force -ErrorAction SilentlyContinue }
    if ($frontendProc -and -not $frontendProc.HasExited) { Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "  Done." -ForegroundColor Green
}
