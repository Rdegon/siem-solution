param(
    [string]$IngestUrl = "https://192.168.1.35/ingest/json",
    [string]$StatePath = "C:\ProgramData\RdegonSIEM\collector-state.json",
    [int]$BatchSize = 500,
    [switch]$InstallTask,
    [string]$TaskName = "RdegonSIEMCollector",
    [string[]]$Channels = @(
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Initialize-Tls {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

function Ensure-StateDirectory {
    $dir = Split-Path -Parent $StatePath
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

function Load-State {
    if (-not (Test-Path $StatePath)) {
        return @{}
    }
    try {
        return Get-Content -Raw -Path $StatePath | ConvertFrom-Json -AsHashtable
    } catch {
        return @{}
    }
}

function Save-State([hashtable]$State) {
    Ensure-StateDirectory
    ($State | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -Path $StatePath
}

function Convert-EventData([xml]$XmlEvent) {
    $payload = @{}
    foreach ($node in @($XmlEvent.Event.EventData.Data)) {
        $name = [string]$node.Name
        if (-not $name) {
            continue
        }
        $payload[$name] = [string]$node.'#text'
    }
    foreach ($node in @($XmlEvent.Event.UserData.ChildNodes)) {
        foreach ($child in @($node.ChildNodes)) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $payload[$child.LocalName] = [string]$child.InnerText
            }
        }
    }
    return $payload
}

function Get-NewEvents([string]$Channel, [long]$LastRecordId) {
    $events = Get-WinEvent -LogName $Channel -MaxEvents $BatchSize -ErrorAction SilentlyContinue
    if (-not $events) {
        return @()
    }
    $fresh = $events | Where-Object { $_.RecordId -gt $LastRecordId } | Sort-Object RecordId
    return @($fresh)
}

function Convert-ToPayload($EventRecord) {
    $xmlString = $EventRecord.ToXml()
    $xml = [xml]$xmlString
    $system = $xml.Event.System
    $eventData = Convert-EventData $xml
    return @{
        source_type = "windows_event_json"
        collector = "powershell"
        source = $env:COMPUTERNAME
        host = @{ name = $env:COMPUTERNAME }
        computer_name = $EventRecord.MachineName
        channel = [string]$EventRecord.LogName
        provider = [string]$EventRecord.ProviderName
        event_id = [int]$EventRecord.Id
        event_code = [string]$EventRecord.Id
        record_id = [int64]$EventRecord.RecordId
        level = [string]$EventRecord.LevelDisplayName
        task = [string]$EventRecord.TaskDisplayName
        opcode = [string]$EventRecord.OpcodeDisplayName
        keywords = [string]::Join(",", @($EventRecord.KeywordsDisplayNames))
        time_created = $EventRecord.TimeCreated.ToUniversalTime().ToString("o")
        message = [string]$EventRecord.Message
        event = @{
            provider = [string]$EventRecord.ProviderName
            id = [string]$EventRecord.Id
            code = [string]$EventRecord.Id
            type = "windows_event"
        }
        windows = @{
            system = @{
                computer = [string]$system.Computer
                event_record_id = [string]$system.EventRecordID
                execution = @{
                    process_id = [string]$system.Execution.ProcessID
                    thread_id = [string]$system.Execution.ThreadID
                }
            }
            event_data = $eventData
            xml = $xmlString
        }
    }
}

function Send-Batch([array]$Batch) {
    if (-not $Batch.Count) {
        return $null
    }
    $json = $Batch | ConvertTo-Json -Depth 10
    return Invoke-RestMethod -Method Post -Uri $IngestUrl -ContentType "application/json" -Body $json
}

function Install-CollectorTask {
    $quotedScript = '"' + $PSCommandPath + '"'
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $quotedScript"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Scheduled task installed:" $TaskName
}

if ($InstallTask) {
    Install-CollectorTask
    exit 0
}

Initialize-Tls
$state = Load-State
$batch = @()

foreach ($channel in $Channels) {
    $lastRecordId = 0
    if ($state.ContainsKey($channel)) {
        $lastRecordId = [long]$state[$channel]
    }
    $events = Get-NewEvents -Channel $channel -LastRecordId $lastRecordId
    foreach ($event in $events) {
        $batch += Convert-ToPayload $event
        if ([long]$event.RecordId -gt $lastRecordId) {
            $lastRecordId = [long]$event.RecordId
        }
    }
    $state[$channel] = $lastRecordId
}

if ($batch.Count -gt 0) {
    $response = Send-Batch -Batch $batch
    Save-State -State $state
    Write-Host ("Sent {0} events to {1}" -f $batch.Count, $IngestUrl)
    if ($response) {
        $response | ConvertTo-Json -Depth 4
    }
} else {
    Write-Host "No new Windows events to send."
}
