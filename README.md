<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunting: Unauthorized TOR Usage


## Objective

Detect and investigate potential TOR browser usage within the corporate environment. The project focuses on identifying behavior where users visit TOR-related websites, download and install the browser, execute it. It also includes tracking temporary files (.txt) created and later deleted as part of the installation or usage process.
### Skills Learned

- Deployed a Virtual Machine in Microsoft Azure and onboarded it to Microsoft Defender for Endpoint
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

### SCENARIO
## Threat Event (Unauthorized TOR Usage)

# Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there

---

## Steps
### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-06-28T18:45:19.3405724Z`. These events began at `2025-06-28T18:18:11.148502Z`.

Query to locate events:
```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-joh  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, CommandLine = InitiatingProcessCommandLine
```
![Screenshot 2025-06-29 211940](https://github.com/user-attachments/assets/74b711be-6064-442d-bbc2-65cae6a3321e)


---
### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-06-28T18:18:11.8784169Z` , a `labuser` on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

Query to locate events:
```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-joh"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp,DeviceName, FileName, FolderPath, SHA256, Account= InitiatingProcessAccountName,ProcessCommandLine
```

![Screenshot 2025-06-29 214133](https://github.com/user-attachments/assets/698feb5a-b7b0-413a-a3b1-21fe2de6483d)


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

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-28T18:18:11.1485089Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-28T18:24:11.8784169Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-28T18:18:53.7886073Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-28T18:19:29.7425232Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-28T18:19:26.116468Z` - Connected to `94.23.88.117` on port `443`.
  - 2025-06-28T18:19:26.116468Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional `TOR-related` traffic was detected, indicating that user `labuser` maintained an active TOR browser session.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-28T18:45:19.3405724Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "threat-hunt-joh" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for `anonymous browsing purposes`, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-joh` by the user `labuser`. The device was isolated, and the user's direct manager was notified.




