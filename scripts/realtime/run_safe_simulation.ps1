param(
  [int]$Port = 8080,
  [switch]$SkipHttpTransfer
)

$ErrorActionPreference = "Stop"

function Write-Ok {
  param([string]$Message)
  Write-Host "[OK] $Message"
}

function Write-Info {
  param([string]$Message)
  Write-Host "[..] $Message"
}

$tempRoot = Join-Path $env:TEMP "edr_realtime_demo"
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

$serverProcess = $null
try {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output EDR_DEMO_T1059_001"
  Write-Ok "Triggered T1059.001"

  if (-not $SkipHttpTransfer) {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $python) {
      Write-Warning "python was not found. Skipping T1105 localhost HTTP transfer. Re-run with Python available or use -SkipHttpTransfer."
    } else {
      $httpRoot = Join-Path $tempRoot "http"
      New-Item -ItemType Directory -Force -Path $httpRoot | Out-Null

      $payloadName = "EDR_DEMO_T1105_edr_demo.txt"
      $payloadPath = Join-Path $httpRoot $payloadName
      Set-Content -LiteralPath $payloadPath -Value "EDR_DEMO_T1105 safe localhost content" -Encoding ASCII

      $serverArgs = @("-m", "http.server", [string]$Port, "--bind", "127.0.0.1", "-d", $httpRoot)
      $serverProcess = Start-Process -FilePath $python.Source -ArgumentList $serverArgs -PassThru -WindowStyle Hidden
      Start-Sleep -Seconds 2

      $downloadDir = "C:\Users\Public\Downloads"
      New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
      $downloadPath = Join-Path $downloadDir $payloadName
      $uri = "http://127.0.0.1:{0}/{1}" -f $Port, $payloadName
      $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
      if ($null -ne $curl) {
        & $curl.Source -sS --max-time 5 -o $downloadPath $uri
      } else {
        Invoke-WebRequest -Uri $uri -OutFile $downloadPath -UseBasicParsing
      }
      Start-Sleep -Milliseconds 500
      Write-Ok "Triggered T1105"
    }
  } else {
    Write-Info "Skipped T1105 because -SkipHttpTransfer was provided."
  }

  & reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRDemo /t REG_SZ /d "cmd.exe /c echo EDR_DEMO_T1547" /f | Out-Null
  Start-Sleep -Milliseconds 700
  & reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EDRDemo /f | Out-Null
  Write-Ok "Triggered T1547.001"

  $rundll32 = Join-Path $env:WINDIR "System32\rundll32.exe"
  if (Test-Path -LiteralPath $rundll32) {
    Start-Process `
      -FilePath $rundll32 `
      -ArgumentList @("url.dll,FileProtocolHandler", "http://example.test/EDR_DEMO_T1218") `
      -WindowStyle Hidden | Out-Null
    Write-Ok "Triggered T1218-lite"
  } else {
    Write-Warning "rundll32.exe was not found; skipping T1218-lite marker."
  }

  & cmd.exe /c "echo EDR_BENIGN_CMD" | Out-Null
  Write-Ok "Triggered benign cmd TN marker"

  & powershell.exe -Command "Write-Output EDR_BENIGN_POWERSHELL" | Out-Null
  Write-Ok "Triggered benign PowerShell TN marker"

  Write-Info "Wait 2-8 seconds, then check Realtime Alerts, Realtime Events, Realtime Evaluation, and Kibana Discover."
} finally {
  if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
    Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
  }
}
