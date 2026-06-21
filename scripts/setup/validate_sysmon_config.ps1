[CmdletBinding()]
param(
    [string]$ConfigPath = "collection/sysmon/sysmon_config.xml",
    [string]$EventFixturePath = "collection/sysmon/fixtures/sysmon_event_1_process_create.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-XmlDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing XML file: $Path"
    }

    [xml]$document = Get-Content -LiteralPath $Path -Raw
    return $document
}

$config = Read-XmlDocument -Path $ConfigPath

if ($config.DocumentElement.Name -ne "Sysmon") {
    throw "Expected root element 'Sysmon' in $ConfigPath."
}

if (-not $config.Sysmon.EventFiltering) {
    throw "Missing EventFiltering section in $ConfigPath."
}

$requiredBlocks = @(
    "ProcessCreate",
    "NetworkConnect",
    "ImageLoad",
    "CreateRemoteThread",
    "ProcessAccess",
    "FileCreate",
    "RegistryEvent",
    "FileCreateStreamHash",
    "DnsQuery"
)

foreach ($blockName in $requiredBlocks) {
    if (-not $config.Sysmon.EventFiltering.$blockName) {
        throw "Missing required Sysmon event block: $blockName"
    }
}

$fixture = Read-XmlDocument -Path $EventFixturePath
$namespaceManager = [System.Xml.XmlNamespaceManager]::new($fixture.NameTable)
$namespaceManager.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")

$eventId = $fixture.SelectSingleNode("//e:System/e:EventID", $namespaceManager)
if (-not $eventId -or $eventId.InnerText -ne "1") {
    throw "Expected fixture to contain Sysmon Event ID 1."
}

$requiredEventDataFields = @(
    "UtcTime",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "CommandLine",
    "CurrentDirectory",
    "User",
    "Hashes",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "ParentCommandLine",
    "ParentUser"
)

foreach ($fieldName in $requiredEventDataFields) {
    $node = $fixture.SelectSingleNode("//e:EventData/e:Data[@Name='$fieldName']", $namespaceManager)
    if (-not $node) {
        throw "Missing required Event ID 1 fixture field: $fieldName"
    }
}

Write-Host "Sysmon Phase 1 config validation passed."
