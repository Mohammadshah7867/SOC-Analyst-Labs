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
---

## 3. Splunk Home

After signing in with the administrator account, the Splunk Home page loaded successfully. This confirmed that the installation was successful and that the Splunk web interface was fully operational.

### Screenshot

![Splunk Home](splunk_home.png)

---

# 4. Verifying Splunk Status

The `splunk status` command was used to verify that the Splunk Enterprise services were running correctly after installation.

### Command

```bash
./splunk status
```

### Screenshot

![Splunk Status](splunk_status.png)

### Findings

- Verified that the `splunkd` service was running successfully.
- Confirmed that all required helper processes were active.
- Validated that the Splunk installation was operating correctly.
- Confirmed the Splunk server was ready for use.

---

# 5. Splunk CLI Help

The `splunk help` command was used to display the available command-line options for administering and managing Splunk Enterprise.

### Command

```bash
./splunk help
```

### Screenshot

![Splunk CLI Help](splunk_help.png)

---

# 5. Splunk Universal Forwarder Installation

The Splunk Universal Forwarder was installed on the same Ubuntu system as the Splunk Enterprise instance. During startup, a management port conflict was detected because Splunk Enterprise was already using port **8089**. The forwarder was successfully configured to use **port 8090**, allowing both services to run simultaneously.

### Screenshot

![Splunk Universal Forwarder Installation](splunk_forwarder_install.png)

### Findings

- Installed the Splunk Universal Forwarder on Ubuntu Linux.
- Identified a management port conflict on port **8089**.
- Reconfigured the forwarder to use management port **8090**.
- Successfully started the Universal Forwarder without errors.
- Verified the installation completed successfully.

---

# 6. Splunk Universal Forwarder Status

After installation, the Universal Forwarder status was verified using the Splunk CLI. The output confirmed that the **splunkd** service and all helper processes were running correctly.

### Screenshot

![Splunk Universal Forwarder Status](splunk_forwarder_status.png)

### Findings

- Verified the Universal Forwarder service was running.
- Confirmed **splunkd** was active.
- Verified all helper processes were running successfully.
- Confirmed the forwarder was ready for data forwarding and log collection.

---

## Skills Demonstrated

- Splunk Universal Forwarder Installation
- Linux Administration
- Command Line (CLI)
- Splunk Service Management
- Port Conflict Resolution
- Log Collection Preparation

### Findings

- Displayed the available Splunk CLI commands.
- Reviewed command syntax and administrative options.
- Demonstrated the use of the Splunk command-line interface.
- Verified access to built-in command documentation.

### Findings

- Successfully authenticated using the administrator account.
- Verified access to the Splunk Home interface.
- Confirmed the installation and configuration were successful.
- Splunk was ready for log ingestion and analysis.
