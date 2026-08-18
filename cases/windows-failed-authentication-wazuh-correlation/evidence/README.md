# Evidence manifest and redaction policy

This directory records the evidence used for the case without publishing sensitive account information.

## Evidence register

| ID | Source | Observation | Publication status |
|---|---|---|---|
| E-01 | Windows Security log | 4625 at 02:39:44 | Documented as a structured timeline entry |
| E-02 | Windows Security log | 4625 at 02:39:55 | Documented as a structured timeline entry |
| E-03 | Windows Security log | 4625 at 02:40:03 | Documented as a structured timeline entry |
| E-04 | Windows Security log | 4625 at 02:40:14 | Documented as a structured timeline entry |
| E-05 | Wazuh alert | Rule 60122, level 5, “Logon Failure - Unknown user or bad password” | Documented in case README |
| E-06 | Windows Security log | 4624 at 02:40:56: SYSTEM, Type 5, Negotiate, services.exe, no source IP | Documented with account-safe fields |
| E-07 | Windows Security log | 4624 at 02:41:09: expected user, Type 7, Negotiate | Account identifier redacted |

## Screenshot policy

No screenshots are included because no safely redacted source images were supplied for publication. This avoids fabricating evidence or accidentally exposing the Microsoft-connected email address.

Before adding any future screenshot:

1. replace the full Microsoft email address with `<REDACTED_MICROSOFT_ACCOUNT>`;
2. inspect the full image, including search bars, filters, expanded JSON/XML, terminal history, window titles, and taskbar notifications;
3. remove hostnames, IP addresses, agent IDs, record IDs, and unrelated usernames if they are not needed;
4. retain the original privately and publish only the redacted derivative;
5. verify that OCR or image metadata cannot reveal the removed value;
6. use a descriptive filename and add it to the evidence register.

## Integrity note

The timeline and field values in this case come from the investigation record provided for this controlled lab exercise. No raw EVTX export was supplied to this repository, so the case does not claim independent forensic verification of those values.
