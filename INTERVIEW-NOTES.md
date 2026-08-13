# Interview Cheat Sheet

## 30-second version

I investigated repeated Wazuh Windows audit failures, traced them to
Event ID 5038 and a specific DLL, validated the file's Authenticode
signature, generated its SHA-256 hash, checked reputation in VirusTotal,
correlated the evidence, and documented a likely-benign disposition.

## Key principle

An alert is an investigation lead, not a verdict.

## Escalation triggers

Invalid/unknown signature; unexpected path; positive reputation hits;
suspicious process ancestry; persistence; unusual network activity;
credential access; or other corroborating indicators.
