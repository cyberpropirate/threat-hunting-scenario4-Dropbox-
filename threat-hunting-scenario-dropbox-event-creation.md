# Threat Event (Suspicious Dropbox-Based Data Exfiltration)
**Unauthorized Data Upload Using Dropbox API via Python Script**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded and executed the Python installer `python-3.12.0-amd64.exe` from the Downloads folder using Command Prompt.
2. Silently installed Python to the system using command-line flags.
3. Executed a pre-downloaded Dropbox upload script `updown.py` via `python.exe`.
4. Created a session log file named `dropbox-session-log.txt` on the desktop to mimic upload logs.


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**|Used to detect creation of the simulated Dropbox session log `dropbox-session-log.txt`. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect execution of the Python installer and script-based upload behavior using `python.exe`.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|


---

## Related Queries:
```kql
// Python Installer Execution
DeviceProcessEvents
| where FileName == "python-3.12.0-amd64.exe"
| where DeviceName == "dropboxmb"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
kql
Copy code
// Python Script Execution (includes updown.py)
DeviceProcessEvents
| where DeviceName == "dropboxmb"
| where FileName has_any("python-3.12.0-amd64.exe", "python.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
kql
Copy code
// Dropbox Log File Creation
DeviceFileEvents
| where FileName == "dropbox-session-log.txt"
| where ActionType == "FileCreated"
| where DeviceName == "dropboxmb"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```

---

## Created By:
- **Author Name**: Musie Berhe
- **Author Contact**: 
- **Date**: August 7, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August  7, 2025`  | `Musie Berhe`   
