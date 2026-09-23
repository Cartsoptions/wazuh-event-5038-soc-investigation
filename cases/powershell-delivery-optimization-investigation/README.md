# PowerShell Endpoint Investigation: Delivery Optimization Network Activity

## Case Summary

This case documents a Windows endpoint investigation performed with PowerShell after identifying an established network connection involving local TCP port 7680 and remote IP address `37.60.108.149`.

The investigation correlated the network connection with its owning process, Windows service, parent process, executable configuration, digital signature, file hash reputation, and Delivery Optimization configuration. The collected evidence was consistent with legitimate Windows Delivery Optimization activity.

**Assessment:** Likely Benign  
**Decision:** Close as benign, with telemetry limitations documented.

> Important limitation: the exact remote IP `37.60.108.149` could not be independently mapped to a specific Delivery Optimization peer using Delivery Optimization telemetry because the available ETL parsing commands failed.

---

## Investigation Trigger

During review of established TCP connections, the endpoint showed a connection involving:

- Local TCP port: `7680`
- Remote IP: `37.60.108.149`
- Owning process ID: `5860`

Rather than judging the connection from the IP address or port alone, the investigation followed the evidence from network connection to process, service, executable, reputation, and application-specific behaviour.

---

## Investigation Workflow

```text
Network connection
      ↓
Owning PID
      ↓
Process identification
      ↓
Windows service association
      ↓
Parent process
      ↓
Executable/configuration validation
      ↓
Digital signature
      ↓
SHA-256 / reputation
      ↓
Network behaviour validation
      ↓
Delivery Optimization configuration/status
      ↓
Log correlation and limitations
      ↓
SOC verdict
```

---

## 1. Review Established Network Connections

PowerShell was used to review established TCP connections and exclude loopback traffic.

```powershell
Get-NetTCPConnection -State Established |
Where-Object {$_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1'} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

The connection of interest involved TCP port `7680`, remote IP `37.60.108.149`, and PID `5860`.

### Why this mattered

A network connection alone does not determine whether activity is malicious. The owning PID provides the pivot from network evidence into endpoint/process investigation.

---

## 2. Correlate the Connection With PID 5860

```powershell
Get-NetTCPConnection |
Where-Object {$_.OwningProcess -eq 5860} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

This confirmed that the network activity under investigation belonged to PID `5860`.

---

## 3. Identify the Process

```powershell
Get-Process -Id 5860
```

The process was identified as:

```text
svchost.exe
```

`svchost.exe` is a Windows service-hosting process, so identifying the process name alone was insufficient. The next question was which service PID 5860 was hosting.

---

## 4. Identify the Windows Service Associated With PID 5860

```powershell
Get-CimInstance Win32_Service |
Where-Object {$_.ProcessId -eq 5860} |
Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName
```

The PID was associated with:

```text
Service Name : DoSvc
Display Name : Delivery Optimization
Process ID   : 5860
```

The service configuration referenced:

```text
C:\Windows\System32\svchost.exe -k NetworkService -p
```

This was an important correlation because the network connection was no longer an unidentified `svchost.exe` process. It was associated with the Windows Delivery Optimization service.

---

## 5. Investigate the Parent Process

The process metadata was queried with CIM:

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId = 5860" |
Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine
```

The parent PID was then investigated:

```powershell
Get-Process -Id 1332 |
Select-Object Name, Id
```

The parent was identified as:

```text
services.exe
PID: 1332
```

This parent-child relationship was consistent with a Windows service being hosted by `svchost.exe`.

### Investigation note

Direct retrieval of the executable path from the process object did not provide a useful path during the investigation, including after confirming the PowerShell session was elevated. The service configuration was therefore used to identify the configured executable path. This limitation is documented rather than silently replaced with an assumption.

---

## 6. Validate the Executable's Digital Signature

The configured Windows executable was checked with Authenticode:

```powershell
Get-AuthenticodeSignature "C:\Windows\System32\svchost.exe"
```

The signature status was valid.

The signer certificate was inspected with:

```powershell
(Get-AuthenticodeSignature "C:\Windows\System32\svchost.exe").SignerCertificate.Subject
```

The signer information was consistent with Microsoft Windows / Microsoft Corporation.

### Why this mattered

A legitimate-looking filename is not enough. Malware can use names that resemble Windows processes. Path and signature validation provide stronger evidence about the executable being investigated.

---

## 7. Calculate the SHA-256 Hash

```powershell
Get-FileHash "C:\Windows\System32\svchost.exe" -Algorithm SHA256
```

The SHA-256 value was collected during the investigation and checked for reputation. The full hash is intentionally not reproduced here because it was not retained in the case notes used to build this report.

VirusTotal showed:

```text
0 / 70 detections
```

This was supporting evidence only. A zero-detection result does not by itself prove that a file is benign.

---

## 8. Validate TCP 7680 Against Delivery Optimization Behaviour

Microsoft documentation was consulted to understand whether the observed network behaviour was expected for Delivery Optimization.

Microsoft documents TCP port `7680` for peer-to-peer communication between Delivery Optimization clients.

This provided an important correlation:

```text
PID 5860
  ↓
svchost.exe
  ↓
DoSvc / Delivery Optimization
  ↓
TCP 7680
  ↓
Port usage consistent with documented Delivery Optimization P2P behaviour
```

Vendor documentation was used to validate behaviour rather than assuming that an unfamiliar port was suspicious.

---

## 9. Inspect Delivery Optimization Status

```powershell
Get-DeliveryOptimizationStatus |
Select-Object Status, DownloadMode, PercentPeerCaching,
BytesFromPeers, BytesFromLanPeers, BytesFromInternetPeers,
BytesToLanPeers, BytesToInternetPeers, NumPeers,
PredefinedCallerApplication
```

The endpoint consistently reported:

```text
Status       : Caching
DownloadMode : Lan
```

Two particularly useful records demonstrated actual peer-caching behaviour.

### Peer-caching record 1

```text
PercentPeerCaching : 86.62%
BytesFromPeers     : 14,680,064
BytesFromLanPeers  : 14,680,064
NumPeers           : 8
Caller             : WU Client Download
```

### Peer-caching record 2

```text
PercentPeerCaching   : 83.88%
BytesFromPeers       : 71,303,168
BytesFromLanPeers    : 71,303,168
BytesToInternetPeers : 22,020,096
NumPeers             : 10
Caller               : WU Client Download
```

These results demonstrated that peer functionality was genuinely active on the endpoint rather than merely enabled in configuration.

---

## 10. Confirm the Configured Download Mode

The Delivery Optimization-specific command was used to query the configured mode directly:

```powershell
Get-DODownloadMode
```

Result:

```text
Lan
```

This independently agreed with the `DownloadMode : Lan` values returned by `Get-DeliveryOptimizationStatus`.

---

## 11. Windows Event Log Correlation

An attempt was first made to discover an event-log channel whose name contained Delivery Optimization:

```powershell
Get-WinEvent -ListLog *DeliveryOptimization* |
Select-Object LogName, RecordCount, IsEnabled
```

No matching event log was registered under that name on the endpoint.

The investigation then searched recent Service Control Manager events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
} -MaxEvents 100 |
Where-Object {$_.Message -match 'DoSvc|Delivery Optimization'} |
Select-Object TimeCreated, Id, ProviderName, Message
```

No matching events were returned in the examined set.

A defined 24-hour window was also searched:

```powershell
$StartTime = (Get-Date).AddHours(-24)

Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Service Control Manager'
    StartTime    = $StartTime
} |
Where-Object {$_.Message -match 'DoSvc|Delivery Optimization'} |
Select-Object TimeCreated, Id, ProviderName, Message
```

Again, no matching events were identified.

### Interpretation

The correct conclusion is not that Delivery Optimization generated no events anywhere. The finding is limited to the logs, provider, criteria, and time window actually examined.

---

## 12. Delivery Optimization ETL Telemetry

Available Delivery Optimization commands were discovered using:

```powershell
Get-Command -Module DeliveryOptimization |
Select-Object Name
```

The investigation attempted to parse Delivery Optimization service logs:

```powershell
Get-DeliveryOptimizationLog -Provider Dosvc
```

The operation failed with:

```text
EtlParseError
PipelineStoppedException
```

The syntax of the analysis cmdlet was then inspected:

```powershell
Get-Command Get-DeliveryOptimizationLogAnalysis -Syntax
```

A connection analysis was attempted:

```powershell
Get-DeliveryOptimizationLogAnalysis -ListConnections
```

This failed with:

```text
FormatException
Input string was not in a correct format.
```

No attempt was made to delete ETL files, clear caches, or modify endpoint logging merely to force the telemetry to parse.

---

## Evidence Correlation

| Evidence | Finding | Analytical Value |
|---|---|---|
| Network | TCP 7680 connection observed | Triggered investigation |
| Owning PID | PID 5860 | Connected network evidence to endpoint process |
| Process | `svchost.exe` | Windows service-host process |
| Service | `DoSvc` / Delivery Optimization | Identified hosted service |
| Parent | `services.exe`, PID 1332 | Consistent with Windows service execution |
| Service path | `C:\Windows\System32\svchost.exe -k NetworkService -p` | Consistent with Windows service configuration |
| Signature | Valid | Supports executable authenticity |
| Signer | Microsoft Windows / Microsoft Corporation | Supports expected Windows binary |
| SHA-256 | Collected | File identity/reputation pivot |
| VirusTotal | 0/70 | No detections at time checked; supporting evidence only |
| TCP 7680 | Documented for Delivery Optimization P2P | Network behaviour consistent with service |
| DO mode | LAN | Confirmed through multiple DO queries |
| DO status | Caching | Delivery Optimization active |
| Peer caching | Actual peer bytes observed | Demonstrates real P2P/cache behaviour |
| SCM logs | No relevant matches in examined searches | No additional correlation obtained |
| DO ETL | Parsing failed | Prevented exact DO telemetry correlation |

---

## Final SOC Verdict

**Assessment:** Likely Benign  
**Decision:** Close as benign, with telemetry limitation documented.

The investigated connection was associated with PID `5860`, identified as `svchost.exe` hosting the Windows Delivery Optimization service (`DoSvc`). The executable configuration pointed to the expected Windows System32 binary, its Authenticode signature was valid, and the signer was consistent with Microsoft Windows. The SHA-256 reputation check returned `0/70` detections on VirusTotal. TCP port `7680` is consistent with documented Delivery Optimization peer-to-peer behaviour, and the endpoint independently reported `DownloadMode: Lan` with actual peer-caching activity. The parent process was `services.exe`, which was consistent with normal Windows service execution. No evidence collected indicated process masquerading, an abnormal parent, or a malicious executable.

However, Delivery Optimization ETL parsing failed. Therefore, the exact remote IP `37.60.108.149` could not be conclusively attributed to a particular Delivery Optimization peer using DO-specific telemetry. The verdict is based on the complete correlated evidence rather than any single indicator.

---

## Investigation Limitations

1. The exact remote IP `37.60.108.149` was not independently mapped to a specific Delivery Optimization peer using DO telemetry.
2. `Get-DeliveryOptimizationLog` failed with `EtlParseError`.
3. `Get-DeliveryOptimizationLogAnalysis -ListConnections` failed with `FormatException`.
4. Service Control Manager searches produced no matching DoSvc/Delivery Optimization events in the examined datasets/windows.
5. The full SHA-256 value was not retained in the notes used to create this report and therefore has not been invented or reconstructed.
6. VirusTotal reputation is supporting evidence and is not proof of benignness by itself.

---

## PowerShell Skills Demonstrated

- `Get-NetTCPConnection`
- `Where-Object`
- `Select-Object`
- `Get-Process`
- `Get-CimInstance Win32_Process`
- `Get-CimInstance Win32_Service`
- CIM `-Filter` versus pipeline filtering
- Parent/child process investigation
- `Get-AuthenticodeSignature`
- `Get-FileHash`
- `Get-WinEvent`
- `-FilterHashtable`
- Time-based event filtering
- `Get-Command`
- `Get-Help`
- `Get-DeliveryOptimizationStatus`
- `Get-DODownloadMode`
- Delivery Optimization log-analysis cmdlets
- Evidence correlation and SOC verdict writing

---

## Analyst Lessons

### A network indicator is an observation, not a verdict

An unfamiliar remote IP or port should trigger investigation, not an immediate malicious classification.

### Follow the evidence chain

A useful endpoint investigation pivots from network connection to PID, process, service, parent process, executable, signature, hash, expected application behaviour, and logs.

### `svchost.exe` is not enough

Because `svchost.exe` hosts Windows services, the analyst should determine which service is associated with the PID before assessing the activity.

### One clean indicator does not prove benignness

A valid Microsoft signature or a `0/70` VirusTotal result is useful, but neither should be used as the sole reason to close an alert.

### Negative results must be scoped correctly

No matching events in a specific 24-hour search does not mean that no relevant events have ever existed.

### Document telemetry limitations

When ETL parsing failed, the limitation was recorded rather than hiding the unsuccessful step or overstating what the evidence proved.

---

## Key Takeaway

> **Traffic is the observation. Process and service correlation provide context. Signature, hash, configuration, vendor documentation, and telemetry provide evidence. The verdict comes from correlation.**

This case demonstrates how PowerShell can be used by an L1 SOC analyst to move from an unusual network connection to an evidence-based endpoint assessment without relying on assumptions.