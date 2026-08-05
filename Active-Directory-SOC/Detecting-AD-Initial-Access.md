# Detecting AD Initial Access

## Objective
Investigate how attackers gain initial access to an Active Directory environment through an AD-integrated web application (IIS), and learn to detect web shell deployment and exploitation using both IIS access logs and Windows/Sysmon endpoint telemetry. This room covers how AD-connected services expand the attack surface beyond a single standalone machine, and walks through a full investigation of a web shell attack from initial reconnaissance through command execution.

## Skills Demonstrated
- Understanding how AD-integrated services (IIS-hosted applications, Exchange, SharePoint, ADFS, VPN gateways) expand the blast radius of a compromise from a single server to the entire domain
- Identifying where IIS authentication activity is logged: Windows Security events (4624/4625) and IIS access logs on the web server, and Event 4776 (credential validation) on the Domain Controller
- Locating and interpreting raw IIS W3C log files (`C:\inetpub\logs\LogFiles\W3SVC1`), including awareness that IIS timestamps are recorded in UTC regardless of server local time
- Reading key IIS log fields (`c-ip`, `cs-uri-stem`, `cs-uri-query`, `cs-method`, `sc-status`, `cs(User-Agent)`) to reconstruct attacker activity from raw HTTP request logs
- Distinguishing normal vs. suspicious IIS traffic patterns: authentication volume, request timing, URI paths, query strings, HTTP methods, and status code distributions
- Recognizing web shell characteristics (`.aspx` scripts accepting commands via HTTP parameters) and understanding why they are a persistent, low-footprint attacker tool
- Identifying the core web shell detection pattern: `w3wp.exe` (the IIS worker process) spawning child processes such as `cmd.exe` or `powershell.exe`, which does not occur during normal IIS operation
- Conducting a full, staged SPL investigation of a web shell attack:
  1. Identifying a directory-scanning source IP via a burst of 404 responses
  2. Pivoting to that IP's successful (200) requests to discover the deployed web shell
  3. Filtering for the web shell's URI to extract attacker-issued reconnaissance commands from the query string
  4. Correlating IIS activity with Sysmon Event ID 1 (process creation) to confirm `w3wp.exe` executing the same commands on the endpoint
  5. Using Sysmon Event ID 11 (file creation) to determine the exact web shell deployment timestamp, with IIS POST-request logs as a fallback if Sysmon data is unavailable
- Recognizing real-world precedent for this attack pattern (HAFNIUM/ProxyLogon China Chopper web shells, 2023 Telerik UI exploitation) and understanding that the underlying detection signature remains consistent across different initial vulnerabilities

## Tools Used
- Splunk (Search & Reporting)
- IIS W3C access logs
- Sysmon (Event ID 1 - Process Creation, Event ID 11 - File Creation)
- Windows Security Event Log (4624, 4625, 4776)
- SPL (Search Processing Language)

## Screenshot 1 - Identifying the Scanning IP (404 Burst)
Before deploying a web shell, attackers typically scan an IIS server for writable paths, which appears in IIS logs as a burst of 404 (Not Found) responses from a single source IP. I queried the `iis` index for all 404 responses, grouped by client IP, and sorted by count:
```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```
One IP address stood out with a dramatically higher 404 count than any other source, identifying it as the directory-scanning attacker IP used throughout the rest of the investigation.

![Scanning IP 404 Burst](detecting_ad_initial_access_scanning_ip_404.png)

## Screenshot 2 - Discovering the Web Shell
Pivoting to the identified IP's successful (200) requests revealed what resources the attacker found and accessed:
```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```
Among the URIs returned, one stood out as a suspicious `.aspx` file located in `/aspnet_client/` - a default IIS directory intended only for ASP.NET client-side scripts, which should never contain executable application code. This directory is writable by the IIS worker process (`w3wp.exe`), making it a common web shell drop location, consistent with real-world China Chopper deployments observed during the 2021 HAFNIUM/ProxyLogon campaign.

![Web Shell Discovery](detecting_ad_initial_access_webshell_discovery.png)

## Screenshot 3 - Extracting Reconnaissance Commands
Filtering IIS logs specifically for requests to the identified web shell file exposed the attacker's activity through the `cs_uri_query` field, since this particular web shell accepts OS commands as a URL parameter:
```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```
The `cs_uri_query` field revealed the reconnaissance commands the attacker executed through the web shell over HTTP.

![Web Shell Reconnaissance Commands](detecting_ad_initial_access_webshell_recon_commands.png)

## Screenshot 4 - Confirming Execution via Sysmon Process Chain
To confirm these commands were actually executed on the host (rather than just requested over HTTP), I pivoted to Sysmon Event ID 1 (process creation), filtering for any process spawned by `w3wp.exe` - something that should essentially never happen during normal IIS operation:
```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```
This confirmed `w3wp.exe` spawning command-line processes executing the same reconnaissance commands observed in the IIS query string, validating that the web shell successfully achieved code execution on the host.

![w3wp.exe Process Chain](detecting_ad_initial_access_w3wp_process_chain.png)

## Screenshot 5 - Determining Web Shell Deployment Time
Finally, to establish exactly when the web shell was written to disk, I queried Sysmon Event ID 11 (File Create) for the web shell's filename:
```spl
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, Image, TargetFilename
```
This returned the precise timestamp the web shell file was created on the target server, anchoring the start of the intrusion timeline. (Note: if Sysmon Event ID 11 data isn't available in a given environment, the same deployment timestamp can typically be recovered from the IIS logs by filtering for the POST request that uploaded the web shell.)

![Web Shell Deployment Timestamp](detecting_ad_initial_access_webshell_deployment_time.png)

## Findings
- Initial access was achieved through directory scanning of an IIS-hosted application, followed by discovery and exploitation of a writable default directory (`/aspnet_client/`) to host a malicious `.aspx` web shell.
- The web shell accepted attacker commands via an HTTP query string parameter, allowing remote command execution without any additional attacker tooling beyond a web browser or HTTP client.
- The core detection signature for this attack - `w3wp.exe` spawning `cmd.exe`/`powershell.exe` - was confirmed directly in Sysmon process creation telemetry, corroborating the activity observed in the IIS access logs.
- IIS logs and endpoint (Sysmon/Security) logs are timestamped differently by default (UTC vs. local server time) and can show minor discrepancies due to buffered logging and network latency; both should be normalized before building a combined timeline during an investigation.
- This attack chain (web-facing application compromise -> web shell -> local code execution) represents the first stage of a broader AD compromise: once code execution is achieved on a domain-joined IIS server, an attacker is positioned to pivot toward credential theft and lateral movement using the techniques covered in later rooms of this module.

## Lessons Learned
- Reinforced that AD-integrated services dramatically increase the impact of what would otherwise be a contained, single-server compromise - a vulnerability in one web application can become a foothold into the entire domain.
- Learned to recognize `w3wp.exe` spawning child processes as a high-confidence detection pattern, since legitimate IIS operation essentially never requires the worker process to launch a command shell (with the narrow exception of legitimate .NET applications invoking the C# compiler, `csc.exe`, which is distinguishable by the commands being executed rather than the parent-child relationship alone).
- Practiced correlating two independent log sources (IIS access logs and Sysmon endpoint telemetry) to validate a single finding from two angles - confirming that a web request wasn't just attempted, but actually resulted in code execution on the host.
- Reinforced the importance of timestamp normalization (UTC vs. local time) when building a cross-source investigation timeline, a detail that's easy to overlook and can lead to incorrect sequencing of events if missed.
- Built a repeatable, staged investigation methodology (scan detection -> artifact discovery -> command extraction -> execution confirmation -> deployment timing) that generalizes well beyond this specific web shell scenario to other web-based initial access investigations.

## References
- [TryHackMe - Active Directory for SOC: Detecting AD Initial Access](https://tryhackme.com/module/active-directory-for-soc)
- [CISA Advisory AA21-062A - Mitigate Microsoft Exchange Server Vulnerabilities](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a)
- [Microsoft - China Chopper Web Shell Analysis](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
