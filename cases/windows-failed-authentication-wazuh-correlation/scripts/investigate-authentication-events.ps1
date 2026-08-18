# Run in an elevated PowerShell session on the investigated Windows endpoint.
# Adjust the time zone/window if the Security log records a different local context.

$start = Get-Date '2026-08-18 02:39:30'
$end   = Get-Date '2026-08-18 02:41:30'

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4625
    StartTime = $start
    EndTime   = $end
}

$events |
    Select-Object TimeCreated, Id, RecordId, ProviderName |
    Sort-Object TimeCreated |
    Format-List

$authEvents = $events |
    Where-Object { $_.Id -in 4624, 4625 }

$authEvents |
    Group-Object Id |
    Sort-Object Name |
    Select-Object Name, Count

$parsed = $authEvents | ForEach-Object {
    $event = $_
    [xml]$xml = $event.ToXml()

    $fields = @{}
    $xml.Event.EventData.Data | ForEach-Object {
        $fields[$_.Name] = $_.'#text'
    }

    [PSCustomObject]@{
        TimeCreated           = $event.TimeCreated
        EventId               = $event.Id
        TargetUserName        = $fields['TargetUserName']
        LogonType             = $fields['LogonType']
        AuthenticationPackage = $fields['AuthenticationPackageName']
        ProcessName           = $fields['ProcessName']
        IpAddress             = $fields['IpAddress']
        Status                = $fields['Status']
        SubStatus             = $fields['SubStatus']
    }
}

$failures = $parsed |
    Where-Object {
        $_.EventId -eq 4625 -and
        $_.TimeCreated -ge $start -and
        $_.TimeCreated -le $end
    }

$successes = $parsed |
    Where-Object {
        $_.EventId -eq 4624 -and
        $_.TimeCreated -ge $failures[0].TimeCreated -and
        $_.TimeCreated -le $end
    } |
    Sort-Object TimeCreated

$failures | Format-List
$successes | Format-List
