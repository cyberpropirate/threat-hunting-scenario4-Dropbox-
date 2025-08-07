# threat-hunting-scenario4-Dropbox-
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="1600" height="623" alt="image" src="https://github.com/user-attachments/assets/6c3adb9b-1248-42a7-8eb7-2b7dfbaea4e5" />


# Threat Hunt Report: DropBox Data Exfiltration
- [Scenario Creation](https://github.com/cyberpropirate/threat-hunting-scenario4-Dropbox-/blob/main/threat-hunting-scenario-dropbox-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
  

##  Scenario

A recent cybersecurity bulletin from CISA warned of adversaries leveraging Python-based tools to exfiltrate data to cloud storage providers, particularly Dropbox, under the guise of legitimate script automation. Management has directed the threat hunting team to investigate any unusual Python installations and outbound activity related to Dropbox API usage to detect potential data leakage or command-and-control staging from developer systems.

### High-Level DropBox Exfiltration IoC Discovery Plan

- **Check `DeviceProcessEvents`** to confirm installation and usage of Python and the Dropbox upload script.
- **Check `DeviceFileEvents`** to detect the creation of artifacts such as upload session logs that stimulate evidence of exfiltration


---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

At `2025-08-07T17:02:07.3203107Z`, user "ecorp" executed the file `python-3.12.0-amd64.exe` from the Downloads folder. This action marked the start of the suspicious activity and was detected using DeviceProcessEvents.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName == "python-3.12.0-amd64.exe"
| where DeviceName == "dropboxmb"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```
<img width="2311" height="1454" alt="{855D8706-ABED-4D50-A38C-E96F6968BD33}" src="https://github.com/user-attachments/assets/aef49fc9-0d87-4511-9d25-ba2092c74344" />


---

### 2. Searched the `DeviceProcessEvents` Table
  
  At `2025-08-07T17:02:06.6976866Z`, user "ecorp" executed the Python installer silently via Command Prompt and at `2025-08-07T17:02:27.4148345Z` ran a Python-based Dropbox upload script using python.exe.



**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "dropboxmb"
| where FileName has_any("python-3.12.0-amd64.exe", "python.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine


```
<img width="2306" height="1406" alt="{B8A96319-F106-4E53-870B-0878CCD8E0F9}" src="https://github.com/user-attachments/assets/6b5d5cca-d6fc-4aed-a38d-b2f2d01cc5fa" />

---

### 3. Searched the `DeviceFileEvents` Table 

At `2025-08-07T17:05:03.8718392Z` the file `dropbox-session-log.txt` was created to simulate session logging of the upload operation.


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName == "dropbox-session-log.txt"
| where ActionType == "FileCreated"
| where DeviceName == "dropboxmb"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```
<img width="2360" height="1437" alt="{0ED5EEF4-28DF-4B65-9C23-30ED43904862}" src="https://github.com/user-attachments/assets/8da786eb-f280-4d40-b60d-cf443a63ae7a" />

---



---

## Chronological Event Timeline 

### 1. Process Execution - Python Installer Launched

- **Timestamp:** `2025-08-07T17:02:06.6976866Z`
- **Event:** User `ecorp` initiated the Python installer `python-3.12.0-amd64.exe` via Command Prompt, indicating the beginning of the suspicious behavior.
- **Action:** Process Execution detected.
- **File Path:** ` C:\Users\ecorp\Downloads\python-3.12.0-amd64.exe`

### 2. Process Execution - Python Installater Execution

- **Timestamp:** `2025-08-07T17:02:07.3203107Z`
- **Event:** The Python executable was formally run on the system from the Downloads folder.
- **Action:** Process execution detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\ecorp\Downloads\python-3.12.0-amd64.exe`

### 3. Script Execution - Python DropBox Upload Script

- **Timestamp:** `2025-08-07T17:02:27.4148345Z`
- **Event:** A Python script (likely updown.py) was executed using python.exe, simulating data exfiltration to Dropbox.
- **Action:** Script execution detected.
- **File Path:** `C:\Users\ecorp\AppData\Local\Programs\Python\Python312\python.exe`

### 4. File Creation - DropBox Session Log File

- **Timestamp:** `2025-08-07T17:05:03.8718392Z`
- **Event:** A file named `dropbox-session-log.txt` was created on disk, simulating a log of Dropbox activity.
- **Action:** FIle Creation Detected.
- **File Path:** `C:\Users\ecorp\Desktop\dropbox-session-log.txt`


---

## Summary

During the investigation, user ecorp on the device dropboxmb executed a Python installer `python-3.12.0-amd64.exe` followed by the execution of a suspected Dropbox CLI script. This script was used to simulate uploading data using the python.exe interpreter. Subsequently, a file named `dropbox-session-log.tx`t was created, simulating session logging activity.

The events were successfully captured using DeviceProcessEvents and DeviceFileEvents in Microsoft Defender for Endpoint. The activity reproduced relevant indicators of compromise (IoCs) useful for detection engineering and analyst training.

---

## Response Taken

The suspicious use of Python and Dropbox-related activity was confirmed on the dropboxmb device under user ecorp. The device was isolated in the lab environment. Findings were documented, and a detection rule will be proposed for any future executions of Python scripts attempting outbound file operations. This scenario has been flagged for further purple team collaboration to build proactive detection use cases.

---
