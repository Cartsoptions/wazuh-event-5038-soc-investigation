# Windows Failed Authentication Investigation & Wazuh Correlation

![Project Type](https://img.shields.io/badge/Project-SOC%20Investigation-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-0E9FFF)
![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2011-0078D4)
![Analysis](https://img.shields.io/badge/Analysis-PowerShell-5391FE)
![Disposition](https://img.shields.io/badge/Disposition-Benign%20Lab%20Activity-2EA44F)

> Tier 1 SOC case study: triaging repeated failed authentications, validating the Wazuh detection, correlating nearby Windows logons, excluding an unrelated service logon, and documenting a defensible disposition.

## Executive summary

On 18 August 2026, four Windows Security **Event ID 4625** failures occurred within 30 seconds. Wazuh correlated the activity as **Rule 60122**, level **5**, with the description **“Logon Failure - Unknown user or bad password.”**

A time-bounded review of nearby Event IDs 4624 and 4625 found two later successful logons. The 02:40:56 success was excluded because its structured fields identified a local service logon: account **SYSTEM**, Logon Type **5**, authentication package **Negotiate**, process `C:\Windows\System32\services.exe`, and no source IP. The 02:41:09 success was the relevant workstation unlock: Logon Type **7** for the expected Microsoft-connected user using **Negotiate**.

**Final disposition: Benign / Controlled Lab Activity.**

The activity was generated intentionally in the home SOC lab. In a production environment, the same pattern would still require identity validation, source review, scope analysis, and escalation if it were unexpected.

## Scope and evidence handling

- Host: Windows 11 endpoint in the home SOC lab
- Telemetry: Windows Security log and Wazuh
- Window investigated: 2026-08-18 02:39:44–02:41:09 local lab time
- Account privacy: the Microsoft email address is represented only as `<REDACTED_MICROSOFT_ACCOUNT>`
- Screenshots: none are published because the source screenshots were not supplied in a safely redacted form
- Evidence policy: no events, fields, or screenshots were fabricated

See [evidence/README.md](evidence/README.md) for the evidence manifest and publication checklist.

## Detection

Wazuh raised the following authentication alert:

| Field | Value |
|---|---|
| Rule ID | `60122` |
| Level | `5` |
| Description | `Logon Failure - Unknown user or bad password` |
| Windows event | Security Event ID `4625` |
| Failure count | `4` |
| Time span | `30 seconds` |

The alert description was treated as an investigation lead. The underlying Windows events were reviewed to establish what actually occurred.

## Investigation timeline

| Time (2026-08-18) | Event | Finding | Analyst decision |
|---|---:|---|---|
| 02:39:44 | 4625 | Failed authentication | Included in failure cluster |
| 02:39:55 | 4625 | Failed authentication | Included in failure cluster |
| 02:40:03 | 4625 | Failed authentication | Included in failure cluster |
| 02:40:14 | 4625 | Failed authentication | Included in failure cluster |
| 02:40:56 | 4624 | SYSTEM; Type 5; Negotiate; `services.exe`; no source IP | Excluded as unrelated service logon |
| 02:41:09 | 4624 | `<REDACTED_MICROSOFT_ACCOUNT>`; Type 7; Negotiate | Correlated as expected workstation unlock |

## Triage workflow

### 1. Collect a narrow event set

```powershell
$start = Get-Date '2026-08-18 02:39:30'
$end   = Get-Date '2026-08-18 02:41:30'

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4625
    StartTime = $start
    EndTime   = $end
}
```

**SOC purpose:** `Get-WinEvent` retrieves Windows telemetry, while `FilterHashtable` performs efficient filtering at collection time. Variables make the time window reproducible and reduce repeated typing.

### 2. Review core metadata

```powershell
$events |
    Select-Object TimeCreated, Id, RecordId, ProviderName |
    Sort-Object TimeCreated |
    Format-List
```

**SOC purpose:** `Select-Object` limits output to decision-relevant properties; `Sort-Object` restores chronological order; `Format-List` exposes full values during close review. Formatting is used for display only, not as pipeline data for later analysis.

### 3. Isolate relevant event IDs

```powershell
$authEvents = $events |
    Where-Object { $_.Id -in 4624, 4625 }
```

**SOC purpose:** `Where-Object` applies analyst-defined conditions to collected objects. The `-in` operator clearly expresses membership in the two authentication event IDs.

### 4. Count and sequence the activity

```powershell
$authEvents |
    Group-Object Id |
    Sort-Object Name |
    Select-Object Name, Count
```

**SOC purpose:** `Group-Object` provides a quick event-frequency summary. `Sort-Object` makes results consistent and easier to compare.

### 5. Parse structured XML fields

```powershell
$parsed = $authEvents | ForEach-Object {
    $event = $_
    [xml]$xml = $event.ToXml()

    $fields = @{}
    $xml.Event.EventData.Data | ForEach-Object {
        $fields[$_.Name] = $_.'#text'
    }

    [PSCustomObject]@{
        TimeCreated          = $event.TimeCreated
        EventId              = $event.Id
        TargetUserName       = $fields['TargetUserName']
        LogonType            = $fields['LogonType']
        AuthenticationPackage= $fields['AuthenticationPackageName']
        ProcessName          = $fields['ProcessName']
        IpAddress            = $fields['IpAddress']
        Status               = $fields['Status']
        SubStatus            = $fields['SubStatus']
    }
}
```

**SOC purpose:** `ToXml()` exposes the event's machine-readable representation and `[xml]` converts it into navigable structured data. `ForEach-Object` processes every event and field. `[PSCustomObject]` creates consistent analyst-friendly records instead of relying on message text, spacing, or localization.

### 6. Perform time-bounded 4624/4625 correlation

```powershell
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
```

**SOC purpose:** a bounded window prevents unrelated historical logons from being mistaken for a resolution of the failure cluster. Event ID alone is insufficient: account, logon type, process, authentication package, and source context must also agree.

## Correlation findings

### Excluded success — 02:40:56

| Field | Observed value |
|---|---|
| Event ID | `4624` |
| Target user | `SYSTEM` |
| Logon type | `5` (service) |
| Authentication package | `Negotiate` |
| Process | `C:\Windows\System32\services.exe` |
| Source IP | Not present |
| Assessment | Unrelated local service logon |

This event was close in time, but it did not represent the interactive user regaining access. Its identity, logon type, process, and lack of a source address consistently identified service activity.

### Correlated success — 02:41:09

| Field | Observed value |
|---|---|
| Event ID | `4624` |
| Target user | `<REDACTED_MICROSOFT_ACCOUNT>` |
| Logon type | `7` (workstation unlock) |
| Authentication package | `Negotiate` |
| Assessment | Expected successful unlock |

This event matched the expected user and interaction type, making it the relevant success following the controlled failures.

## Analyst assessment

### What supports the disposition

- The activity was intentionally generated in a controlled home lab.
- Four 4625 failures formed a short, coherent cluster.
- Wazuh correctly surfaced the failures through Rule 60122.
- The nearby SYSTEM Type 5 logon was investigated and excluded using structured fields.
- The subsequent Type 7 event matched the expected workstation unlock.
- No public evidence contains the user's Microsoft email address.

### Production escalation conditions

The same sequence should be escalated if:

- the user denies generating the failures;
- the source host or IP is unexpected;
- failures target multiple accounts or assets;
- the failures continue after a successful logon;
- privileged accounts are involved;
- geolocation, device, or working hours are anomalous;
- lockout, password-spray, MFA, endpoint, or threat-intelligence signals correlate;
- a Type 3 or Type 10 success follows from a suspicious remote source.

## Conclusion

The Wazuh alert was valid: four failed authentications occurred and were detected as Rule 60122, level 5. Investigation of nearby 4624 successes showed why temporal proximity alone is not enough for correlation. The 02:40:56 event was an unrelated SYSTEM service logon, while the 02:41:09 Type 7 event was the expected Microsoft-connected user's workstation unlock.

**Disposition: Benign / Controlled Lab Activity.**

## Skills demonstrated

`Wazuh Alert Triage` • `Windows Security Events` • `4624/4625 Correlation` • `PowerShell` • `Get-WinEvent` • `FilterHashtable` • `Object Pipelines` • `Structured XML Parsing` • `PSCustomObject` • `Time-Bounded Analysis` • `False-Positive Exclusion` • `Evidence Handling` • `SOC Documentation`

## Repository structure

```text
cases/windows-failed-authentication-wazuh-correlation/
├── README.md
├── evidence/
│   └── README.md
└── scripts/
    └── investigate-authentication-events.ps1
```

## Disclaimer

This case documents controlled home-lab activity for educational and portfolio purposes. The conclusion applies only to the stated evidence and time window.
