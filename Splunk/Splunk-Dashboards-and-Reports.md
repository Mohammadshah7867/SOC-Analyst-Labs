# Splunk Dashboards and Reports

## Objective

This lab demonstrates how Splunk reports can be used to summarize large datasets, identify authentication trends, establish security baselines, and detect abnormal activity using threshold-based searches.

---

## Skills Demonstrated

- Creating Splunk reports
- Using the `stats` command
- Sorting search results
- Saving reports
- Establishing baselines
- Threshold-based detection
- Investigating web logs
- Monitoring HTTP status codes
- Writing SOC detection queries

---

## Tools Used

- Splunk Enterprise
- TryHackMe – Splunk Dashboards & Reports

---

## Screenshot 1 – Initial Data Overview

To begin the lab, I searched all indexed data using `index=*`, set the time range to **All time**, and reviewed the available events before beginning report creation.

![Initial Data Overview](initial_data_overview.png)

---

## Screenshot 2 – VPN Username Report Query

I created a report that counts VPN logins by username using the `stats` command. The results are sorted from the highest number of logins to the lowest, allowing analysts to quickly identify the most active VPN users.

```spl
index=vpn_server
| stats count by Username
| sort - count
```

![VPN Username Report Query](vpn_username_report_query.png)

---

## Screenshot 3 – Creating the Report

The VPN username query was saved as a report named **VPN Logins by Usernames**. This allows analysts to quickly reuse the search without recreating it.

![Creating Report](create_report.png)

---

## Screenshot 4 – Completed VPN Report

The completed report displays VPN login counts for every username. Reports provide an efficient way for SOC analysts to review authentication activity and identify unusual login patterns.

![VPN Username Report](vpn_username_report.png)

---

# Alerting and Detection

## Screenshot 5 – Suspicious Restricted Page Search

To identify potential unauthorized access, I searched for requests to `/restricted.html` while excluding private IP address ranges. Any remaining results represent external systems attempting to access an internal resource.

```spl
index=web_logs URI=/restricted.html NOT Source_IP IN (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)
```

![Restricted Page Search](initial_data_overview.png)

---

## Screenshot 6 – Reviewing HTTP Status Codes

Next, I reviewed the HTTP status codes returned by `/payments.html`. Understanding the normal distribution of response codes helps establish a baseline before creating detection rules.

```spl
index=web_logs URI=/payments.html
```

![Payments Status Codes](payments_status_codes.png)

---

## Screenshot 7 – Establishing a Baseline

I calculated the average number of HTTP 404 responses per hour. This baseline helps determine what is considered normal activity before defining an alert threshold.

```spl
index=web_logs URI=/payments.html status_code=404
| bin _time span=1h
| stats count AS hits BY _time
| eventstats avg(hits) AS avg_hits
| eval avg_hits=round(avg_hits,1)
```

![404 Baseline](payments_404_baseline.png)

---

## Screenshot 8 – Threshold Detection

Finally, I created a threshold-based detection rule that identifies hours where HTTP 404 responses exceed the normal baseline. Any hour with more than 11 responses is flagged for investigation.

```spl
index=web_logs URI=/payments.html status_code=404
| bin _time span=1h
| stats count AS hits BY _time
| where hits > 11
| eval alert="HIGH 404s: ".hits." in 1h (normal: ~7.6/hr)"
```

![404 Threshold Detection](payments_404_threshold.png)

---

---

## Screenshot 9 – Dashboard Edit Mode

Next, I opened the **Web Logs Overview** dashboard and entered **Edit** mode to begin building additional visualizations. Dashboards provide a centralized view of important security information, allowing analysts to quickly monitor activity and identify trends across web server logs.

![Dashboard Edit Mode](web_logs_dashboard.png)

---

## Screenshot 10 – URI Event Distribution

I added a **Pie Chart** panel that displays the distribution of requests by URI. This visualization provides a quick overview of which web pages receive the most traffic and helps identify the most frequently accessed resources.

```spl
index=web_logs
| stats count by URI
| sort - count
```

![URI Event Distribution](uri_pie_chart.png)

---

## Screenshot 11 – Source IP Statistics Table

I then created another **Statistics Table** displaying the **Source_IP**, **URI**, and **status_code** fields. This view helps identify which source IP addresses accessed specific web pages and the HTTP response codes they received, making it useful for investigating suspicious activity and validating web server behavior.

```spl
index=web_logs
| stats count by Source_IP URI status_code
| sort - count
```

![Source IP Statistics Table](source_ip_statistics_table.png)

---

## Screenshot 12 – Completed Web Logs Dashboard

Finally, I completed the dashboard by combining multiple visualizations into a single interface. The dashboard now includes the hourly activity chart, URI distribution pie chart, HTTP status summary table, and Source IP statistics table, providing an organized overview of web server activity for monitoring and investigation.

![Completed Web Logs Dashboard](completed_web_logs_dashboard.png)
