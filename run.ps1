Write-Host "Starting Mock Upstream Server on port 8080..."
$upstream = Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m uvicorn upstream.mock_server:app --host 127.0.0.1 --port 8080" -PassThru

Write-Host "Starting Gateway on port 8000..."
$gateway = Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" -PassThru

Write-Host "Servers are running. Press Ctrl+C to stop."

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "Shutting down servers..."
    Stop-Process -Id $upstream.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $gateway.Id -ErrorAction SilentlyContinue
}
