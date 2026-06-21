param(
  [string]$HostIp = "192.168.213.1"
)

if ([string]::IsNullOrWhiteSpace($HostIp)) {
  throw "HostIp is required. Example: .\scripts\setup\use_host_docker.ps1 192.168.213.1"
}

# These env vars are process-scoped. Run this once in every new PowerShell
# session before starting Docker on the host or running Python commands in the VM.
$env:EDR_DOCKER_HOST = $HostIp
$env:EDR_ELASTICSEARCH_URL = "http://${HostIp}:9200"
$env:EDR_LOGSTASH_URL = "http://${HostIp}:8080"
$env:EDR_KAFKA_BOOTSTRAP_SERVERS = "${HostIp}:9092"
$env:KAFKA_ADVERTISED_HOST = $HostIp

Write-Host "EDR Docker host env configured:"
Write-Host "  EDR_DOCKER_HOST=$env:EDR_DOCKER_HOST"
Write-Host "  EDR_ELASTICSEARCH_URL=$env:EDR_ELASTICSEARCH_URL"
Write-Host "  EDR_LOGSTASH_URL=$env:EDR_LOGSTASH_URL"
Write-Host "  EDR_KAFKA_BOOTSTRAP_SERVERS=$env:EDR_KAFKA_BOOTSTRAP_SERVERS"
Write-Host "  KAFKA_ADVERTISED_HOST=$env:KAFKA_ADVERTISED_HOST"
