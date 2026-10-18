# Helper script to promote a user to system_admin in local development
param(
    [Parameter(Mandatory=$false)]
    [string]$Email
)

if (-not $Email) {
    # If no email provided, list existing users
    Write-Host "No email specified. Querying existing users from database..." -ForegroundColor Yellow
    docker exec -it reversebug-postgres psql -U reversebug -d reversebug -c "SELECT id, email, display_name, platform_role, status, email_verified_at IS NOT NULL as verified FROM users ORDER BY created_at DESC LIMIT 10;"
    $Email = Read-Host "`nEnter the email of the user to promote to system_admin"
}

if ($Email) {
    Write-Host "Promoting $Email to system_admin and verifying email..." -ForegroundColor Cyan
    docker exec -it reversebug-postgres psql -U reversebug -d reversebug -c "UPDATE users SET platform_role = 'system_admin', email_verified_at = COALESCE(email_verified_at, now()) WHERE email = '$Email';"
    Write-Host "`nSuccessfully promoted $Email! Refresh your browser and visit http://localhost:5173/admin" -ForegroundColor Green
}
