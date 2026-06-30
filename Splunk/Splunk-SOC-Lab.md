# Splunk: Setting Up a SOC Lab

## Objective

Install and configure Splunk Enterprise on Ubuntu Linux, create an administrator account, and verify access to the Splunk Web interface.

## Environment

- Platform: TryHackMe
- Operating System: Ubuntu Linux
- Splunk Enterprise 9.x

## Skills Practiced

- Linux Administration
- Splunk Installation
- Splunk Configuration
- Command Line
- SIEM Deployment

---

## 1. Starting Splunk

The Splunk Enterprise service was started from the terminal after installation. During startup, Splunk initialized its services, generated the required certificates, and launched the Splunk Web interface on the default port (8000).

### Command

```bash
cd /opt/splunk/bin
./splunk start --accept-license
```

### Screenshot

![Splunk Start](splunk_start.png)

### Findings

- Successfully started the Splunk Enterprise service.
- Generated the required startup configuration and certificates.
- Confirmed the Splunk Web interface was available on port **8000**.
- Verified the installation completed successfully.
---

---

## 3. Splunk Dashboard

After logging in with the administrator account, the Splunk Enterprise dashboard was successfully loaded. This confirmed that the installation and configuration were completed correctly and that the web interface was fully operational.

### Screenshot

![Splunk Dashboard](splunk_dashboard.png)

### Findings

- Successfully authenticated using the administrator account.
- Verified access to the Splunk Enterprise dashboard.
- Confirmed the installation and initial configuration were successful.
- Splunk was ready for log ingestion and analysis.

---

## Skills Demonstrated

- Linux Administration
- Splunk Enterprise Installation
- Splunk Configuration
- Command Line
- SIEM Deployment
- Web Interface Configuration

## Reference

TryHackMe. *Splunk: Setting Up a SOC Lab*. https://tryhackme.com
