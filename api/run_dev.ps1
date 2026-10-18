$env:Path = "C:\Program Files\Go\bin;" + $env:Path
$env:RB_DATABASE_URL = "postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable"
$env:RB_REDIS_URL = "redis://127.0.0.1:6379/0"
$env:RB_ENV = "development"
$env:RB_HTTP_ADDR = ":8080"
$env:RB_PUBLIC_BASE_URL = "http://localhost:5173"
$env:RB_STORAGE_DIR = "./data/storage"
$env:RB_DATA_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
$env:RB_API_KEY_PEPPER = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
$env:RB_COOKIE_SECURE = "false"
$env:RB_ADMIN_REQUIRE_MFA = "false"
$env:RB_SMTP_HOST = "127.0.0.1"
$env:RB_SMTP_PORT = "1025"
$env:RB_AI_PROVIDER = "mock"
$env:RB_AI_MOCK_ENABLED = "true"

& "C:\Program Files\Go\bin\go.exe" run cmd/api/main.go
