# ReverseBug Local System Launcher
# Launches Docker containers, Go API server, Python worker daemon, and React frontend

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         ReverseBug SecIntel v1.0 Launch Sequence         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RootPath = (Get-Item $PSScriptRoot).Parent.FullName

# 1. Verify Docker Containers
Write-Host "`n[1/4] Checking Docker containers..." -ForegroundColor Yellow
$pgStatus = docker inspect -f '{{.State.Running}}' reversebug-postgres 2>$null
if ($pgStatus -ne "true") {
    Write-Host "Starting Docker containers..." -ForegroundColor Yellow
    docker compose -f "$RootPath\docker-compose.yml" up -d
    Start-Sleep -Seconds 3
} else {
    Write-Host "Docker containers already healthy (PostgreSQL, Redis, Mailpit)." -ForegroundColor Green
}

# 2. Environment Variables
$env:RB_DATABASE_URL = "postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable"
$env:RB_REDIS_URL = "redis://127.0.0.1:6379/0"
$env:RB_ENV = "development"
$env:RB_HTTP_ADDR = ":8080"
$env:RB_PUBLIC_BASE_URL = "http://localhost:5173"
$env:RB_STORAGE_DIR = "$RootPath\api\data\storage"
$env:RB_DATA_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
$env:RB_API_KEY_PEPPER = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
$env:RB_COOKIE_SECURE = "false"
$env:RB_ADMIN_REQUIRE_MFA = "false"
$env:RB_SMTP_HOST = "127.0.0.1"
$env:RB_SMTP_PORT = "1025"
$env:RB_AI_PROVIDER = "mock"
$env:RB_AI_MOCK_ENABLED = "true"

# 3. Start Python Worker in background window
Write-Host "`n[2/4] Starting Python Static Analysis Worker..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$RootPath\worker'; & '.\.venv\Scripts\python.exe' -m app.main"

# 4. Start Go API in background window
Write-Host "`n[3/4] Starting Go API Gateway (:8080)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:Path = 'C:\Program Files\Go\bin;' + `$env:Path; cd '$RootPath\api'; `$env:RB_DATABASE_URL = 'postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable'; `$env:RB_REDIS_URL = 'redis://127.0.0.1:6379/0'; `$env:RB_ENV = 'development'; `$env:RB_DATA_ENCRYPTION_KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='; `$env:RB_API_KEY_PEPPER = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='; & 'C:\Program Files\Go\bin\go.exe' run cmd/api/main.go"

# 5. Start React Frontend
Write-Host "`n[4/4] Starting React Web App (:5173)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$RootPath\web'; npm run dev"

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " ReverseBug Services Successfully Launched!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " -> Web Application:    http://localhost:5173" -ForegroundColor White
Write-Host " -> API Gateway:        http://localhost:8080" -ForegroundColor White
Write-Host " -> API Health Check:   http://localhost:8080/healthz" -ForegroundColor White
Write-Host " -> Mailpit SMTP Inbox: http://localhost:8025" -ForegroundColor White
Write-Host " -> Test APK Created:   $RootPath\test-vulnerable-app.apk" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
