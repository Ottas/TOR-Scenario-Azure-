<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunting: Unauthorized TOR Usage


## Objective

Detect and investigate potential TOR browser usage within the corporate environment. The project focuses on identifying behavior where users visit TOR-related websites, download and install the browser, execute it. It also includes tracking temporary files (.txt) created and later deleted as part of the installation or usage process.
### Skills Learned

- Threat Hunting & Detection – Identified TOR browser activity through file and process behavior.
- Log Analysis (KQL) – Used Kusto Query Language to query device logs, file events, and process executions.
- Ability to generate and recognize attack signatures and patterns.
- Endpoint Security – Monitored and analyzed Windows telemetry for suspicious actions.
- Microsoft Sentinel – Leveraged Azure-native SIEM capabilities to query and visualize data.
- Ability to generate and recognize attack signatures and patterns.

### Tools Used

- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser
---
## Steps
### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-06-28T18:45:19.3405724Z`. These events began at `2`.

Query to locate events:
```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-joh  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, CommandLine = InitiatingProcessCommandLine
```
![asdada](https://github.com/user-attachments/assets/2255fc95-4445-447d-99d5-c3d0a5164028)

---
### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at , an labuser on the "threat-hunt-lab" device ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder, using a command that triggered a silent installation.

Query to locate events:
```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-joh"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp,DeviceName, FileName, FolderPath, SHA256, Account= InitiatingProcessAccountName,ProcessCommandLine
```

![lalal](https://github.com/user-attachments/assets/d09123a5-f786-47a3-be46-a49c260d4bd7)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user “labuser” actually opened the tor browser.There was evidence that they did open it at `2025-06-28T18:18:53.7886073Z`
There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

Query to locate events:
```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-joh"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName,ProcessCommandLine , FolderPath, SHA256
| order by Timestamp desc
```

![3333333](https://github.com/user-attachments/assets/ecb0dace-46b9-4344-abac-cb1e89c43c9e)

---

### 4.  Searched the DeviceNetworkEvents Table for TOR Network Connections

Searched the `DeviceNetoworkEvents` Table for any indication the tor browser was used to establish a connection using any of the known tor ports. at `2025-06-28T18:19:29.7425232Z`, the user account `labuser` on the device `threat-hunt-joh` successfully established a network connection (ActionType: ConnectionSuccess) to the remote IP address `142.202.51.68` over port `9001`, which is commonly used by the `TOR` network.There were a few other connections.
Query to locate events:

Query to locate events:
```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-joh"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")  //tor -> knwon ports
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl,FileName =  InitiatingProcessFileName,FolderPath =  InitiatingProcessFolderPath  
| order by Timestamp desc
```

![dasdadadad](https://github.com/user-attachments/assets/3ac1d490-4699-40e2-888b-9bdd3b90cb16)

---

## Chronological Event Timeline 




