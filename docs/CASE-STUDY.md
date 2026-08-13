# Case Study Summary

## Detection
Wazuh generated repeated `Windows audit failure event` alerts from a Windows 11 endpoint.

## Triage
Raw event inspection identified Windows Event ID 5038 and traced the alert to `avamsi.dll` under the Surfshark Endpoint Protection SDK.

## Validation
PowerShell Authenticode verification returned `Valid / Signature verified`.

## Enrichment
The file's SHA-256 was calculated and searched in VirusTotal. The observed report showed `0/71` detections.

## Disposition
Likely Benign / False Positive, with Moderate–High confidence based on correlated evidence.

## Key SOC Lesson
An alert is an investigation lead—not a verdict. Multiple independent sources of evidence should be correlated before closure or escalation.
