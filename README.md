# How to create dashboards in Splunk

## Example use cases
- Malware_Detecting
- Critical_Folder_Access
- Windows_Update_Fail
- Brute_Force

##  - Malware_Detecting

![image](https://github.com/user-attachments/assets/6f436a6a-9aa8-43bc-a9c5-009b747f322a)

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

![image](https://github.com/user-attachments/assets/16601aca-55c8-4234-81b4-191ab29d44d2)

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

![image](https://github.com/user-attachments/assets/f3fc740b-8b7e-42ed-a0be-74779d3aca2d)

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

![image](https://github.com/user-attachments/assets/0123ea54-6012-4740-bd9f-b54dffba31b9)

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
