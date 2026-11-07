# SOC Home Lab — Part 1: Splunk SIEM & PowerShell Threat Detection

## Project Overview

This project focuses on building a Security Operations Center (SOC) home lab using Splunk Enterprise, Windows Event Logs, and Microsoft Sysmon. The goal is to gain hands-on experience with security monitoring, log analysis, threat detection, and incident investigation.

In Part 1, I configured Splunk to collect Windows security telemetry, created a detection rule for encoded PowerShell execution, and investigated a simulated security event.

The project demonstrates the process of collecting endpoint logs, identifying potentially suspicious activity, creating automated alerts, and determining whether detected behavior is malicious or benign.

## Technologies Used

| Technology | Purpose |
|---|---|
| Splunk Enterprise | SIEM platform for collecting, searching, and analyzing security logs |
| Microsoft Sysmon | Detailed Windows endpoint activity monitoring |
| Windows Event Logs | Windows authentication, application, and system event collection |
| Splunk Processing Language (SPL) | Log searching, field extraction, and detection logic |
| PowerShell | Generating controlled test activity and analyzing encoded commands |
| MITRE ATT&CK | Mapping detection behavior to known adversary techniques |

## 1. Environment Setup

I installed Splunk Enterprise on a Windows PC to serve as the central platform for collecting and analyzing security events.

I configured Splunk to ingest three Windows event log channels:

- **Security:** Authentication activity and security-related events.
- **System:** Operating system events and service activity.
- **Application:** Application-generated events and errors.

After configuring the data inputs, I verified that Windows Security events were successfully indexed by Splunk.

**Verification query:**

```spl
index=main sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
```

This query displays the different Windows Security Event IDs collected by Splunk and their event counts.

**Screenshot:** Windows Security Event IDs displayed in Splunk.

## 2. Sysmon Installation and Configuration

To improve endpoint visibility, I installed Microsoft Sysmon, which provides detailed information about process creation and other system activities.

After installing Sysmon, I verified that events were being generated in Windows Event Viewer under:

`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

Because the Sysmon channel was not available through Splunk's graphical data input interface, I manually configured its collection through the `inputs.conf` file.

**Sysmon input configuration:**

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
checkpointInterval = 5
current_only = 0
disabled = 0
index = main
start_from = oldest
renderXml = 1
```

After restarting Splunk, I verified that Sysmon events were successfully indexed.

```spl
index=main source="*Sysmon*"
| stats count by source sourcetype
```

This confirmed that Sysmon telemetry was being collected and was available for investigation.

**Screenshot:** Sysmon events successfully ingested into Splunk.

## 3. Process Creation Monitoring

The next objective was to investigate process execution using Sysmon Event ID 1.

Sysmon Event ID 1 records process creation information, including the executable path, command-line arguments, parent process, and associated user.

Since Sysmon logs were collected in XML format, I used SPL's `rex` command to extract relevant fields.

**Process investigation query:**

```spl
index=main source="*Sysmon*" "<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<ProcessImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<ProcessUser>[^<]*)</Data>"
| search ProcessImage="*powershell.exe" OR ProcessImage="*pwsh.exe"
| table _time ProcessImage CommandLine ParentImage ProcessUser
| sort -_time
```

The resulting table provided visibility into PowerShell execution and parent-child process relationships.

During initial analysis, I observed legitimate applications launching PowerShell, demonstrating that PowerShell execution alone does not necessarily indicate malicious activity.

**Screenshot:** Extracted process creation fields in Splunk.

## 4. Detection Rule — Encoded PowerShell Execution

### Objective

Develop a detection rule to identify PowerShell processes launched with the `-EncodedCommand` argument.

Attackers may use encoded PowerShell commands to obscure their intentions. However, encoded commands also have legitimate administrative uses, making further investigation necessary.

**MITRE ATT&CK mapping:** T1059.001 — Command and Scripting Interpreter: PowerShell.

### Simulated Activity

To test the detection, I generated a harmless encoded PowerShell command:

```powershell
$command = 'Write-Output "SOC Lab Test Successful"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($command)
)
powershell.exe -NoProfile -EncodedCommand $encoded
```

This simulated the use of an encoded PowerShell command without performing malicious actions.

### Detection Query

```spl
index=main source="*Sysmon*" "<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<ProcessImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<ProcessUser>[^<]*)</Data>"
| where like(lower(ProcessImage), "%powershell.exe")
| where like(lower(CommandLine), "%-encodedcommand%")
| table _time host ProcessImage CommandLine ParentImage ProcessUser
| sort -_time
```

The detection successfully identified three encoded PowerShell process creation events during testing.

This rule specifically detects the full `-EncodedCommand` argument. It does not cover every possible abbreviation or method of executing encoded PowerShell.

**Screenshot:** Encoded PowerShell detection results.

## 5. Automated Alert Configuration

After validating the detection query, I configured a scheduled Splunk alert.

| Configuration | Value |
|---|---|
| Alert name | SOC Encoded PowerShell Execution |
| Alert type | Scheduled |
| Cron expression | `*/5 * * * *` |
| Search earliest time | `-5m@m` |
| Search latest time | `@m` |
| Trigger condition | Number of Results greater than 0 |
| Severity | Low |

The alert was configured to run every five minutes and identify matching events within the preceding five-minute window.

After generating another test event, Splunk successfully triggered the alert and returned the matching PowerShell process.

**Screenshot:** Triggered Alerts page showing the scheduled detection.

## 6. SOC Incident Investigation — SOC-001

### Alert Details

| Field | Finding |
|---|---|
| Incident ID | SOC-001 |
| Alert name | SOC Encoded PowerShell Execution |
| Event date | November 4, 2026 |
| Event time | 5:55:43 PM |
| Event source | Sysmon Event ID 1 |
| Executable | powershell.exe |
| Detection indicator | -EncodedCommand |
| Severity | Low |
| Classification | Benign Positive |

### Investigation Process

After the scheduled alert triggered, I examined the matching Sysmon event in Splunk.

I reviewed the executable path, command-line arguments, parent process information, and event timestamp.

The command-line arguments contained a Base64-encoded PowerShell payload. To determine its purpose, I extracted the encoded string and decoded it using PowerShell:

```powershell
$encoded = "PASTE_BASE64_HERE"

[Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($encoded)
)
```

The decoded payload was:

```powershell
Write-Output "SOC Lab Test Successful"
```

This confirmed that the event was generated by my authorized lab test.

### Findings and Disposition

The detection rule correctly identified PowerShell execution using the `-EncodedCommand` argument.

The decoded command was harmless and was intentionally executed to validate the detection.

**Final classification:** Benign Positive — Authorized Security Test.

**Impact:** No harmful activity identified from the test payload.

**Remediation:** No remediation required.

**Screenshot:** Alert investigation results showing the detected command.

## 7. Challenges and Troubleshooting

Several issues occurred during the project:

**Sysmon was not listed in Splunk's event log collection interface.**

I resolved this by manually adding the Sysmon Operational channel to `inputs.conf` and restarting Splunk.

**Sysmon XML fields were not automatically extracted.**

I used the SPL `rex` command to extract event information, including process images, command lines, parent processes, and user accounts.

**Initial detection queries produced no results or regex errors.**

I inspected raw XML events to verify that process creation telemetry existed, then refined the detection query using `like()` to identify encoded PowerShell execution.

These troubleshooting steps reinforced the importance of validating data ingestion, understanding log formats, and testing detection logic before configuring automated alerts.

## 8. Key Takeaways

Through this project, I gained hands-on experience with:

- Configuring Splunk Enterprise for Windows event collection.
- Collecting endpoint telemetry using Microsoft Sysmon.
- Investigating process creation events and parent-child relationships.
- Writing SPL queries and extracting fields from XML logs.
- Developing and testing a security detection rule.
- Configuring scheduled alerts.
- Investigating encoded PowerShell execution.
- Distinguishing suspicious behavior from confirmed malicious activity.
- Mapping detection logic to MITRE ATT&CK.

## 9. Future Improvements

Planned improvements include:

- Developing detection rules for repeated failed authentication attempts.
- Creating a SOC dashboard to visualize security activity.
- Improving detection coverage for additional PowerShell arguments and execution techniques.
- Adding a separate Windows virtual machine to simulate an enterprise endpoint.
- Documenting additional SOC investigations and incident response workflows.

---
