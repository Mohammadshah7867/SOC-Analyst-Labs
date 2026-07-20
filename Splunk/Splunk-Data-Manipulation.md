# Splunk: Data Manipulation

## Objective

This lab focuses on how Splunk ingests, parses, and normalizes machine data. It covers building a custom Splunk application, configuring a scripted data input, and verifying that raw log data is successfully collected and indexed. These skills are foundational for correctly structuring data so it can be searched, correlated, and used to build accurate detections.

## Skills Demonstrated

- Understanding Splunk's data ingestion and parsing pipeline
- Navigating Splunk's default application structure
- Creating a custom Splunk application
- Writing a custom scripted data input
- Configuring `inputs.conf`
- Restarting Splunk services to apply configuration changes
- Verifying log ingestion through SPL search

## Tools Used

- Splunk Enterprise
- Python 3 (custom scripted input)
- TryHackMe – Splunk: Data Manipulation

## Task 1-4 – Introduction, Scenario Briefing, How Splunk Processes Data, Exploring Configuration Files

These tasks covered the conceptual foundation for the lab: how Splunk ingests raw machine data, breaks it into events, and uses configuration files (`inputs.conf`, `props.conf`, `transforms.conf`, `fields.conf`) to control parsing and indexing behavior. Splunk applies these configuration files in a defined precedence order, with settings in an app's `local` directory taking priority over `default`. No hands-on lab actions were required for these sections.

# Creating a Splunk App

## Screenshot 1 – Reviewing Default Applications

Before creating a custom app, I navigated to **Settings → Apps → Manage Apps** to review Splunk's default installed applications. The instance listed 26 total apps, confirming 25 default apps were present prior to creating a custom one.

![Manage Apps Page](dataapp_manage_apps.png)

## Screenshot 2 – Creating the App

I created a new custom Splunk application named **DataApp** using the **Create App** form, which generates the app's standard directory structure automatically.

![Create App Form](dataapp_create_form.png)

## Screenshot 3 – Reviewing the App Directory Structure

Using the command line, I navigated to the new app's directory and listed its contents, confirming the standard Splunk app structure: `bin`, `default`, `local`, and `metadata`.

```bash
cd /opt/splunk/etc/apps/DataApp
ls
```

![DataApp Folder Structure](dataapp_folder_structure.png)

## Screenshot 4 – Building and Testing a Custom Script

Inside the `bin` directory, I created a simple Python script, `samplelogs.py`, to generate sample log output. I then executed the script directly to confirm it produced valid output before configuring Splunk to ingest it.

```bash
echo 'print("This is a sample log...")' > samplelogs.py
python3 samplelogs.py
```

![Samplelogs Script Test](samplelogs_script_test.png)

## Screenshot 5 – Configuring the Scripted Input

I created an `inputs.conf` file in the app's `local` directory to tell Splunk to run the script on a five-second interval and route its output to the `main` index using a custom sourcetype and host value.

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
INDEX = main
SOURCETYPE = testing
HOST = test
INTERVAL = 5
```

![DataApp inputs.conf](dataapp_inputs_conf.png)

## Screenshot 6 – Restarting Splunk

After saving the configuration, I restarted Splunk for the new scripted input to take effect.

```bash
/opt/splunk/bin/splunk restart
```

![Splunk Restart](splunk_restart.png)

## Screenshot 7 – Verifying Log Ingestion

Finally, I switched to the DataApp context in Splunk Web and searched `index=main` with the time range set to **All time**, confirming that the scripted input was successfully generating and ingesting log events on schedule.

```spl
index=main
```

![DataApp Search Results](dataapp_search_results.png)

## Conclusion

This lab provided hands-on experience building a custom Splunk application from the ground up, including writing a scripted data input, configuring `inputs.conf`, and verifying successful log ingestion through SPL. This exercise reinforced how Splunk apps are structured, how scripted inputs are registered and scheduled, and how configuration changes must be applied through a service restart. These skills form the foundation for more advanced data parsing techniques, including event boundary configuration, multi-line event handling, sensitive data masking, and custom field extraction, covered in later sections of this lab.

## References

1. TryHackMe. *Splunk: Data Manipulation*. https://tryhackme.com
2. Splunk Inc. *Splunk Enterprise Documentation*. https://docs.splunk.com/Documentation/Splunk
3. Splunk Inc. *Search Processing Language (SPL) Search Reference*. https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Aboutthesearchlanguage
