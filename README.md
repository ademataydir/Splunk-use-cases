# How to create dashboards in Splunk

## Example use cases
- Malware_Detecting
- Critical_Folder_Access
- Windows_Update_Fail
- Brute_Force

##  - Malware_Detecting

![image](https://github.com/user-attachments/assets/217345bd-8a47-4404-b7c3-fa7c97dc7576)

© Splunk Inc.

## What kind of query should be written for these dashboards?

### Infected_Host
source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" 
(signature="Trojan*" OR signature="Virus*" OR signature="Worm*")

| stats dc(host) as Host

### Detail_List
source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" 
(signature="Trojan*" OR signature="Virus*" OR signature="Worm*")

| stats count by host user signature

### Total_Malware_Count
source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" 
(signature="Trojan*" OR signature="Virus*" OR signature="Worm*")

| stats count as Total_Malware

### Update_Status_isn’t_Success
index="main" source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" category=update

| search status!=success

| stats latest(date) as date, latest(status) as status, latest(Product_Version) as Product_Version by host category

| table date host category status Product_Version

### Latest_Update_Status
index="main" source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" category=update

| stats latest(date) as date, latest(status) as status, latest(Product_Version) as Product_Version by host category

| table date host category status Product_Version

## - Critical_Folder_Access

![image](https://github.com/user-attachments/assets/137b4a35-a665-466b-9651-b3273b6a920f)

© Splunk Inc.

## What kind of query should be written for these dashboards?

### Suspicious_Access_by_Host
*\\Windows\\System32\\config\\*

| bin span=1d _time

| stats count by host _time

| rename host AS "Host", count AS "Access Count"

### Suspicious_Access_Details
*\\Windows\\System32\\config\\*

| stats count by host user CommandLine

| sort -count

| rename host AS "Host", user AS "User", CommandLine AS "Command Used", count AS "Access Count"

### Time_Line
*\\Windows\\System32\\config\\*

| timechart span=1d count by host

## - Windows_Update_Fail

![image](https://github.com/user-attachments/assets/213cb07a-59b6-4ca9-b777-516963aa0e96)

© Splunk Inc.

## What kind of query should be written for these dashboards?

### Total_Count_By_Host
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host

### HOST
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host, Message

| chart sum(count) by host

### Message
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host, Message

### FAILURE COUNT BY HOST
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host

| sort -count

### Content_of_the_failure
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host, Message

| sort -count

### Content_of_the_failure_2
source="WinEventLog:System" "Windows Update"

| search (Message=*error* OR Message=*fail*)

| stats count by host, Message

## - Brute_Force

![image](https://github.com/user-attachments/assets/4f844b57-ce88-4f87-8ab0-ef35ddcb463d)

© Splunk Inc.

### Host / Date
source=* (EventCode=4625 OR EventCode=4624)

| eval action=if(EventCode=4625, "failure", "success")

| bin span=1d _time

| stats count(eval(action="failure")) as Failure_Count, count(eval(action="success")) as Success_Count by host, _time

| where Failure_Count > 100 AND Success_Count > 0

| stats count by host _time

### Details
source=* (EventCode=4625 OR EventCode=4624)

| eval action=if(EventCode=4625, "failure", "success")

| bin span=1d _time

| stats count(eval(action="failure")) as Failure_Count, count(eval(action="success")) as Success_Count by host, _time

| where Failure_Count > 100 AND Success_Count > 0

| stats count by host _time Failure_Count Success_Count

| table _time host Failure_Count Success_Count

| sort -_time

### Note
This content has been prepared for personal learning purposes related to the installation of Splunk software. All screenshots and software are the property of Splunk Inc. This page is not intended for commercial use.
