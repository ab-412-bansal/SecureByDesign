$ErrorActionPreference = 'Stop'
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Write-Host 'Running backend tests...'
Push-Location (Join-Path $ProjectDir 'backend')
try {
    python -m pytest tests -q
    if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
}
finally {
    Pop-Location
}

Write-Host 'Installing locked frontend dependencies and building...'
Push-Location (Join-Path $ProjectDir 'frontend')
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    npm audit --omit=dev
    if ($LASTEXITCODE -ne 0) { throw 'Production npm dependency audit failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
}
finally {
    Pop-Location
}

Write-Host 'Validating Docker Compose...'
docker compose -f (Join-Path $ProjectDir 'docker-compose.yml') config -q
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose validation failed.' }

Write-Host 'Checking shell script syntax...'
Push-Location (Join-Path $ProjectDir 'scripts')
try {
    Get-ChildItem -Filter '*.sh' | ForEach-Object {
        bash -n $_.Name
        if ($LASTEXITCODE -ne 0) { throw "Shell syntax check failed: $($_.Name)" }
    }
}
finally {
    Pop-Location
}

Write-Host 'All available project checks passed.'