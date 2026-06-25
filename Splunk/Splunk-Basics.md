# Splunk Basics

## Objective
Learn the fundamentals of Splunk Search & Reporting by performing searches, filtering events, and analyzing Windows logs.

## Tools Used
- Splunk Enterprise
- TryHackMe Splunk: Exploring SPL

## Skills Demonstrated
- Searching indexes
- Filtering events
- Using the Time Picker
- Working with fields
- Search operators
- SPL commands
- Basic log analysis

## Investigation Steps

### 1. Initial Search
Query:
`index=windowslogs`

![Initial Search](initial_search.png)

### 2. SourceIP Analysis
I reviewed the SourceAddress field to identify the IP addresses generating the most events in the Windows logs.

![Source Address Analysis](source_address_analysis.png)

### 3. Time Filtering
I used Splunk's Date Time Range filter to narrow the search to events occurring between 08:05 AM and 08:06 AM on April 15, 2022. Time filtering helps analysts focus on activity during a specific incident window.

![Time Filtering](time_filtering.png)

### 4. Search Operators
Brief explanation...

*(Insert screenshot)*

### 5. Structuring Results
Brief explanation...

*(Insert screenshot)*

### 6. Transforming Commands
Brief explanation...

*(Insert screenshot)*

### Findings
- Successfully searched Windows logs.
- Filtered events using SPL.
- Identified high-volume SourceIP values.
- Applied time-based filtering.
- Used SPL commands to organize and analyze results.

## Skills Practiced
- Splunk Search & Reporting
- SPL
- Log Analysis
- Windows Event Logs
- SOC Investigation
