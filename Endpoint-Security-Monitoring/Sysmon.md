# Sysmon

## Objective
System Monitor (Sysmon) is a Windows system service and device driver that monitors and logs detailed system activity to the Windows event log, including process creation, network connections, and file creation time changes. Unlike default Windows logging, Sysmon requires a configuration file to define what activity to capture, and is commonly paired with a SIEM in production environments to detect malicious or anomalous behavior on an endpoint. This room also covers practical threat hunting techniques using Sysmon logs to detect activity such as Metasploit/meterpreter connections.

## Skills Demonstrated
- Understanding the purpose and architecture of Sysmon as an endpoint monitoring tool
- Interpreting Sysmon configuration files and the include/exclude rule philosophy
- Identifying key Sysmon Event IDs and their use cases (process creation, network connections, image loads, registry changes, DNS queries, etc.)
- Installing and starting Sysmon with a custom configuration file via PowerShell
- Navigating to and reviewing the Sysmon Operational log in Event Viewer
- Filtering large event logs using `Get-WinEvent` and XPath queries for targeted threat hunting
- Hunting for Metasploit/meterpreter activity via suspicious network connections and process images
- Connecting to a remote lab machine via VPN and RDP for hands-on endpoint work

## Tools Used
- Sysmon (Sysinternals)
- Windows Event Viewer
- PowerShell (Get-WinEvent, XPath filtering)
- OpenVPN / TryHackMe VPN
- Microsoft Remote Desktop (Windows App)
- TryHackMe – Sysmon

## Sysmon Configuration Overview
Sysmon requires a configuration file to define how it should analyze and log events. Two configuration philosophies were covered in this room:
- **SwiftOnSecurity's config** — starts broad and **excludes** known-normal activity, reducing noise while retaining high-quality detection coverage.
- **ION-Storm's config** — takes a more proactive approach by primarily using **include** rules, only logging specifically defined activity.

Neither approach is universally "correct" — the right choice depends on a SOC team's tooling, log volume tolerance, and detection maturity.

## Key Sysmon Event IDs
| Event ID | Activity Monitored | Use Case |
|---|---|---|
| 1 | Process Creation | Detect known-bad or misspelled/masquerading processes |
| 3 | Network Connection | Detect suspicious outbound connections (e.g., scanning tools, C2 ports like 4444) |
| 7 | Image Loaded (DLL) | Detect DLL injection/hijacking (high system load — use selectively) |
| 8 | CreateRemoteThread | Detect process injection techniques (e.g., Cobalt Strike beacons) |
| 11 | File Created | Detect dropped files, ransomware note filenames, etc. |
| 12/13/14 | Registry Event | Detect persistence mechanisms and credential abuse |
| 15 | FileCreateStreamHash | Detect files hidden in alternate data streams |
| 22 | DNS Event | Exclude known-safe domains to surface anomalous DNS queries |

## Screenshot 1 – Sysmon Operational Event Log
After connecting to the lab machine, I confirmed Sysmon was already installed and actively logging to `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational` in Event Viewer, populated with real-time events including DNS queries and file creation activity.
![Sysmon Operational Log](sysmon_event_viewer_operational_log.png)

## Hunting Metasploit
Metasploit's default listener port is 4444, making Event ID 3 (Network Connection) combined with destination port filtering a common hunting technique. Rather than relying on Event Viewer's limited built-in filter, I used `Get-WinEvent` with an XPath query to filter directly on the `DestinationPort` field:

```bash
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"]=4444' | Format-List *
```

Filtering strictly on `DestinationPort=4444` returned no results in this particular log — meaning the actual malicious connection did not use the "textbook" Metasploit port. Broadening the search to inspect all Event ID 3 entries surfaced the real connection:

## Screenshot 2 – Suspicious Network Connection Detected
Full detail output of the flagged network connection event, showing a suspicious process reaching out over a non-default port.
![Hunting Metasploit Network Connection](hunting_metasploit_network_connection.png)

Key details from the flagged event:
- **Image:** `C:\Users\THM-Threat\Downloads\shell.exe`
- **ProcessId:** 3660
- **User:** THM\THM-Threat
- **DestinationIp:** 10.13.4.34
- **DestinationPort:** 444 (not the default 4444)

## Findings
- The OpenSSH-related logs, PowerShell provider events, and Sysmon Operational log all confirmed active, correctly configured logging on the target endpoint.
- The exclude-heavy (SwiftOnSecurity) vs. include-heavy (ION-Storm) config philosophies represent a real tradeoff SOC teams must decide on based on their environment and tooling maturity.
- Filtering strictly on the "textbook" Metasploit port (4444) returned zero results in this log — the actual malicious connection used port **444** instead. This reinforced that adversaries don't always use default ports, and a hunt scoped too narrowly around a single expected indicator (like a specific port number) can miss real activity.
- In this case, the strongest indicator of compromise wasn't the port at all — it was the process image itself: `shell.exe` executed directly from a user's Downloads folder, a highly atypical and suspicious execution path.
- The lab environment came with Sysmon pre-installed and pre-configured, confirmed via a "service already registered" message when a fresh install was attempted.

## Lessons Learned
- Don't over-anchor a hunt on a single well-known indicator (like Metasploit's default port 4444) — always broaden the search (e.g., all Event ID 3 connections) if the primary indicator returns no results, since attackers can and do change defaults.
- Piping `Get-WinEvent` output to `Format-List *` is far more useful than the default table view when hunting, since it exposes every field (Image, ProcessId, User, Source/DestinationIp, etc.) needed to pivot an investigation.
- On large `.evtx` files (tens of thousands of events), Event Viewer's status bar count is a faster and more reliable way to get an exact match count than piping `Get-WinEvent` results through additional PowerShell cmdlets, which can take a long time to process on bigger logs.
- Setting up remote access (VPN + RDP) is its own skill separate from the room content itself — troubleshooting OpenVPN installation via Homebrew, correctly locating `.ovpn` config files, and connecting via Microsoft's Windows App were all valuable practical exercises in their own right.
- Always verify machine-specific credentials provided partway through a room rather than assuming generic credentials shown earlier in the room still apply.

## References
1. TryHackMe. *Sysmon*. https://tryhackme.com
2. Microsoft Docs. *Sysmon*. https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
3. SwiftOnSecurity. *sysmon-config*. https://github.com/SwiftOnSecurity/sysmon-config
4. ION-Storm. *sysmon-config*. https://github.com/ion-storm/sysmon-config
5. MITRE ATT&CK. *Software*. https://attack.mitre.org/software/
