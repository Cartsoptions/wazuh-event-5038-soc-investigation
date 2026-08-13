# 🛡️ Wazuh SOC Investigation: Windows Code Integrity Event ID 5038

![Project Type](https://img.shields.io/badge/Project-SOC%20Investigation-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-0E9FFF)
![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2011-0078D4)
![Analysis](https://img.shields.io/badge/Analysis-PowerShell-5391FE)
![Threat Intel](https://img.shields.io/badge/Threat%20Intel-VirusTotal-394EFF)

> **Portfolio case study:** A hands-on Tier 1 SOC investigation covering alert triage, Windows Event ID analysis, artifact validation, hashing, threat-intelligence enrichment, evidence correlation, and analyst disposition.

---

## Executive Summary

While monitoring a Windows 11 endpoint in my Wazuh home SOC lab, I observed a high volume of **Windows audit failure** alerts. Instead of treating the generic Wazuh rule description as proof of compromise, I investigated the underlying Windows telemetry.

The events were traced to **Windows Event ID 5038**, a Code Integrity event. The affected artifact was:

```text
C:\Program Files\Surfshark\Endpoint Protection SDK\amsi\x64\avamsi.dll
```

I then:

1. verified the Wazuh infrastructure and endpoint were healthy;
2. filtered the events to Event ID 5038;
3. identified the affected DLL;
4. validated its Authenticode signature with PowerShell;
5. generated its SHA-256 hash;
6. performed a VirusTotal hash reputation lookup; and
7. correlated all evidence before making a disposition.

### Final disposition

**Likely Benign / False Positive — Moderate-to-High confidence**

The investigated file had a valid signature and the observed VirusTotal report showed **0/71 detections**. No additional evidence of compromise was identified in the scoped investigation.

> A valid signature or 0/71 VirusTotal result is **not sufficient by itself** to declare a file safe. The verdict was based on correlation of multiple independent observations.

---

## Skills Demonstrated

- SIEM monitoring and alert triage
- Wazuh threat hunting
- Windows Security Event analysis
- Event filtering and field-level investigation
- Endpoint artifact identification
- PowerShell-based file validation
- Authenticode signature verification
- SHA-256 hashing
- Threat-intelligence enrichment
- Evidence correlation
- False-positive analysis
- SOC ticket documentation
- Analyst escalation/closure decision-making

---

## Lab Architecture

```mermaid
flowchart LR
    A[Windows 11 Endpoint] -->|Windows telemetry| B[Wazuh Agent]
    B --> C[Wazuh Manager]
    C --> D[Wazuh Indexer]
    D --> E[Wazuh Dashboard]
    E --> F[SOC Investigation]
    F -->|Signature + Hash| G[PowerShell]
    F -->|Hash Reputation| H[VirusTotal]
    G --> I[Evidence Correlation]
    H --> I
    I --> J[Analyst Verdict]
```

### Lab stack

| Component | Purpose |
|---|---|
| Oracle VirtualBox | Virtualization platform |
| Ubuntu Server | Hosts Wazuh server components |
| Wazuh Manager | Event analysis |
| Wazuh Indexer | Security data storage/search |
| Wazuh Dashboard | Threat hunting and investigation |
| Windows 11 Pro | Monitored endpoint |
| Wazuh Agent | Endpoint telemetry collection |
| PowerShell | File signature and hash validation |
| VirusTotal | Reputation enrichment |

---

# Investigation Walkthrough

## 1. Validate Wazuh health

Before trusting the alert data, I first verified that the Wazuh server components were healthy.

The Wazuh Manager, Indexer, and Dashboard were checked individually:

```bash
sudo systemctl is-active wazuh-manager
sudo systemctl is-active wazuh-indexer
sudo systemctl is-active wazuh-dashboard
```

### Wazuh Manager

![Wazuh Manager active](images/02-wazuh-manager-active.png)

### Wazuh Indexer

![Wazuh Indexer active](images/03-wazuh-indexer-active.png)

### Wazuh Dashboard

![Wazuh Dashboard active](images/04-wazuh-dashboard-active.png)

**Analyst reasoning:** validate the monitoring infrastructure before drawing conclusions from SIEM telemetry.

---

## 2. Verify the Windows endpoint

The Wazuh dashboard confirmed that one endpoint was active and reporting.

![Wazuh overview](images/05-wazuh-overview.png)

The endpoint list showed the Windows agent in **Active** state.

![Wazuh active endpoint](images/06-agent-active.png)

Opening the endpoint confirmed recent keep-alives and endpoint telemetry.

![Endpoint overview](images/07-endpoint-overview.png)

---

## 3. Enter Threat Hunting

The Threat Hunting view showed a substantial volume of Windows events for the endpoint.

![Threat Hunting dashboard](images/08-threat-hunting-dashboard.png)

I moved to the raw event table to examine individual alerts rather than relying only on dashboards.

![Wazuh Events table](images/09-events-table.png)

---

## 4. Isolate the Windows audit failures

The event set was filtered to:

```text
rule.description: Windows audit failure event
```

![Windows audit failure filter](images/10-audit-failure-filter.png)

This produced a large number of matching events. The generic Wazuh rule description did not explain the underlying Windows condition, so I opened an event's document details.

---

## 5. Identify Windows Event ID 5038

The raw document fields showed:

```text
data.win.system.eventID: 5038
```

and a Windows Code Integrity message indicating that the image hash of a file was not valid.

![Event ID 5038 document details](images/11-event-5038-document-details.png)

I then filtered the event set on `data.win.system.eventID = 5038`. The resulting view isolated the relevant Code Integrity events.

![Event ID 5038 filtered events](images/13-event-id-5038-filtered.png)

### Analyst interpretation

Event ID 5038 is a **Code Integrity** event. It can indicate a software/configuration issue, file modification, signature/integrity problem, disk/device issue, or potentially malicious tampering. It therefore requires investigation but should **not** be automatically classified as malware.

---

## 6. Identify the affected file

Within the event details, the field:

```text
data.win.eventdata.param1
```

identified the artifact:

```text
\Device\HarddiskVolume3\Program Files\Surfshark\Endpoint Protection SDK\amsi\x64\avamsi.dll
```

![Affected file path in Wazuh](images/14-param1-filepath-document.png)

I filtered the events on `data.win.eventdata.param1` using the identified Surfshark Endpoint Protection path. The resulting event set isolated activity associated with the affected DLL.

![Filtered file path results](images/17-filepath-filter-result.png)

---

## 7. Verify the Authenticode signature

On the Windows endpoint, I opened **PowerShell as Administrator** and ran:

```powershell
Get-AuthenticodeSignature "C:\Program Files\Surfshark\Endpoint Protection SDK\amsi\x64\avamsi.dll" |
Format-List Status,StatusMessage,SignerCertificate
```

Observed:

```text
Status        : Valid
StatusMessage : Signature verified.
```

![Authenticode signature verification](images/18-authenticode-signature.png)

### Analyst interpretation

A valid Authenticode signature supported the legitimacy of the artifact, but it was treated as **one piece of evidence**, not a final verdict.

---

## 8. Generate the SHA-256 hash

I collected the exact file hash with:

```powershell
Get-FileHash "C:\Program Files\Surfshark\Endpoint Protection SDK\amsi\x64\avamsi.dll" -Algorithm SHA256
```

Observed SHA-256:

```text
B3614BC967F92876FB0B4D2BFC263B9FA88A10964B5D3B4AE06C8DE61C0EC35D
```

![SHA-256 file hash](images/19-sha256-hash.png)

The hash allowed the exact artifact to be reputation-checked without initially uploading the local DLL.

---

## 9. Enrich with VirusTotal

The SHA-256 was searched in VirusTotal.

Observed result:

```text
0 / 71
No security vendors flagged this file as malicious
```

![VirusTotal result](images/20-virustotal-0-of-71.png)

### Analyst interpretation

The observed VirusTotal result strengthened the benign hypothesis but did **not prove safety**. Reputation data was correlated with the signature, expected software path, Wazuh event context, and absence of additional compromise indicators.

---

# Evidence Correlation

| Evidence | Observation | Analyst interpretation |
|---|---|---|
| Wazuh rule | Windows audit failure | Needs triage |
| Windows Event ID | 5038 | Code Integrity issue |
| Event provider | Microsoft-Windows-Security-Auditing | Native Windows auditing |
| File | `avamsi.dll` | Installed endpoint-protection path |
| Authenticode | Valid | Supports legitimacy |
| Signature message | Signature verified | Supports legitimacy |
| SHA-256 | Collected | Exact artifact identified |
| VirusTotal | 0/71 | No observed vendor detection |
| Other compromise evidence | None identified in scope | Weakens malicious hypothesis |

## Verdict

### **Likely Benign / False Positive**

**Confidence:** Moderate–High

This verdict was based on the combined weight of the evidence, not on a single tool.

---

# SOC Ticket Example

**Alert:** Windows Code Integrity Audit Failure — Event ID 5038  
**Detection source:** Wazuh  
**Affected asset:** Windows 11 endpoint / Agent 001  
**Initial severity:** Medium  
**Disposition:** Likely Benign / False Positive

### Investigation actions

1. Confirmed Wazuh Manager, Indexer, and Dashboard were active.
2. Confirmed the Windows endpoint was connected.
3. Reviewed repeated Windows audit failure alerts.
4. Opened raw event details.
5. Identified Windows Event ID 5038.
6. Identified `avamsi.dll` from `data.win.eventdata.param1`.
7. Filtered Wazuh events by Event ID and file path.
8. Verified the Authenticode signature.
9. Collected SHA-256.
10. Performed VirusTotal reputation lookup.
11. Correlated evidence.
12. Assigned a likely-benign disposition.

### Closure note

```text
Investigation completed. Windows Event ID 5038 referenced avamsi.dll
within the Surfshark Endpoint Protection SDK directory. Authenticode
verification returned Valid / Signature verified. The SHA-256 hash was
collected and an existing VirusTotal report showed 0/71 detections.
No additional evidence of compromise was identified within the scope
of this investigation. Alert classified as likely benign/false positive.

Recommendation: continue monitoring for changes in file hash, digital
signature, reputation, path, or associated endpoint behavior.
```

---

# How I Would Explain This in an Interview

> In my Wazuh home lab, I investigated repeated Windows audit failure alerts from a monitored Windows 11 endpoint. I first validated that the Wazuh infrastructure and agent were healthy, then used Threat Hunting to narrow the events. Opening the raw event fields showed Windows Event ID 5038, a Code Integrity event, and I traced it to an `avamsi.dll` file under an endpoint-protection software directory. I verified the file's Authenticode signature with PowerShell, generated its SHA-256 hash, and performed a VirusTotal reputation lookup. The signature was valid and the observed report showed 0 out of 71 detections. I correlated those results with the file location and absence of additional compromise indicators, then documented the alert as likely benign. The key lesson was that I treated the alert as an investigation lead rather than relying on a single indicator.

### If asked: “Does 0/71 mean the file is safe?”

No. It means none of the engines shown in that VirusTotal report detected the hash at that time. I used it as **supporting evidence**, alongside signature verification, path/context, and endpoint telemetry.

### If asked: “What would make you escalate?”

I would escalate if I found:

- an invalid or unknown signature;
- an unexpected/user-writable path;
- positive reputation hits;
- suspicious process ancestry;
- persistence;
- unusual outbound connections;
- credential-access activity;
- an unexplained hash change; or
- other correlated signs of compromise.

---

# Lessons Learned

1. **A SIEM rule description is not the root cause.** Raw event fields matter.
2. **“Audit failure” does not automatically mean failed authentication.**
3. **An alert is an investigation lead—not a verdict.**
4. **A valid digital signature is evidence, not proof of safety.**
5. **VirusTotal 0/71 is evidence, not proof of safety.**
6. **Good SOC decisions come from correlation.**
7. **Infrastructure health should be validated before analyzing endpoint telemetry.**
8. **Documenting the reasoning is as important as obtaining the technical result.**

---

# Future Improvements

- Deploy Sysmon for richer process/network telemetry.
- Collect Microsoft Defender operational logs.
- Investigate process ancestry around the affected DLL.
- Compare the local artifact with a vendor-distributed known-good copy.
- Record file version and publisher metadata.
- Check disk/device health if Event 5038 persists.
- Build a custom Wazuh detection/use case for repeated Event 5038 activity.
- Automate hash reputation enrichment.
- Develop a suspicious-file triage playbook.
- Add MITRE ATT&CK mapping where behavior provides enough context.

---

# Repository Structure

```text
wazuh-event-5038-soc-investigation/
├── README.md
├── INTERVIEW-NOTES.md
├── docs/
│   └── CASE-STUDY.md
└── images/
    ├── 02-wazuh-manager-active.png
    ├── 03-wazuh-indexer-active.png
    ├── 04-wazuh-dashboard-active.png
    ├── 05-wazuh-overview.png
    ├── 06-agent-active.png
    ├── 07-endpoint-overview.png
    ├── 08-threat-hunting-dashboard.png
    ├── 09-events-table.png
    ├── 10-audit-failure-filter.png
    ├── 11-event-5038-document-details.png
    ├── 13-event-id-5038-filtered.png
    ├── 14-param1-filepath-document.png
    ├── 17-filepath-filter-result.png
    ├── 18-authenticode-signature.png
    ├── 19-sha256-hash.png
    └── 20-virustotal-0-of-71.png
```

---

# References

- [Microsoft Learn — Event 5038](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5038)
- [Wazuh Documentation — Windows log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)
- [Wazuh Documentation — Threat Hunting](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html)
- [VirusTotal Documentation — How it works](https://docs.virustotal.com/docs/how-it-works)

---

## Disclaimer

This repository documents a controlled cybersecurity home-lab investigation for educational and portfolio purposes. The verdict applies only to the evidence observed during this investigation. A valid digital signature or zero-detection reputation result must never be used as the sole basis for declaring an unknown file safe.
