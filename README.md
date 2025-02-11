(Disclaimer: This article presents a fictional threat hunting scenario created for educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat hunting skills, analytical thinking, and investigative processes for professional development. It does not reflect or promote any actual security incidents or breaches.)

# Threat Hunt Report: Bryce Montgomery
## Platforms Used
- EDR: Microsoft Defender
- Query Language: KQL (Kusto Query Language)
## Scenario
The Risk Department of a large tech company has raised concerns regarding Bryce Montgomery, a company executive, who is suspected of unauthorized access or theft of intellectual property. Given Montgomery’s executive privileges, he has full administrative access to his workstation (corp-ny-it-0334), allowing him to bypass certain security controls. Additionally, due to a Data Loss Prevention (DLP) exception for executives, standard monitoring and restrictions on file transfers do not apply, increasing the risk of potential data exfiltration.
To address these concerns, I was tasked to investigate Bryce Montgomery's computer for any signs of unusual activity or potential data theft.
## Step 1
1.0 Known Information
- Username: bmontgomery
- Workstation: corp-ny-it-0334

1.1 Objective - Identify the “thumbprint” (any type) of one of the first corporate files that was accessed or interacted with by Bryce Montgomery during the investigation.

1.2 Identified SHA256 hash of first accessed file with the following query:
```kql
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334" 
| where InitiatingProcessAccountName == "bmontgomery"
| where ActionType in ("FileModified", "FileCopied", "FileAccessed")
| project Timestamp, DeviceId, ActionType, FileName, SHA256  
| order by Timestamp asc
```
1.3 Query Results:
![image](https://github.com/stevenrim/threathunt1/blob/main/step1screenshot.png?raw=true)

## Step 2
2.0 Known Information
- There are shared workstations in some areas of the campus that have a generic user profile established for guests.

2.1 Objective - Identify the DeviceName of any other workstation Bryce Montgomery may have used.

2.2 Leveraged the hashes found in Step 1 to identify renamed files that were located on another workstation.
```kql
DeviceFileEvents
| where SHA256 in ("ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d", "657c41d860ce131c3a1d397a5fcd405d4e71b404ce10b775a1b8359763551c3b","3d21356bcf39032d2bb6e772bdfd131f754bb66d8b8f404e4de0ee4a8f6142c8")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, PreviousFileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

2.3 Query Results:
![image](https://github.com/stevenrim/threathunt1/blob/main/step2screenshot.png?raw=true)

## Step 3
3.0 Known Information
- N/A

3.1 Objective - Identify the FileName of the process that interacted with the renamed files on the lobby machine.

3.2 Searched for all file names and previous file names and analyzed the action type and initiating process file name columns.
```kql
union DeviceFileEvents, DeviceProcessEvents, DeviceEvents
| where FileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf", "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", "temp___2bbf98cf.pdf")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, PreviousFileName, InitiatingProcessFileName, ActionType, SHA256
| order by Timestamp asc
```
3.3 Query Results:
![image](https://github.com/stevenrim/threathunt1/blob/main/step3screenshot.png?raw=true)

## Step 4
4.0 Known Information
- N/A

4.1 Objective - Enter the full path of one of the files that was created as a result of steghide.exe running.

4.2 Used the initiating process file name found in step 3 to search for process command line. Found the full path of created file.
```kql
  DeviceProcessEvents
    | where ProcessCommandLine contains "steghide.exe"
    | project FileName, ProcessCommandLine
```
4.3 Query Results:
![image](https://github.com/stevenrim/threathunt1/blob/main/step4screenshot.png)

## Step 5
5.0 Known Information
- N/A

5.1 Objective - Enter the full path of one of the files that was created as a result of steghide.exe running.

5.2 Used the initiating process file name found in step 3 to search for process command line. Found the full path of created file.
```kql
  DeviceProcessEvents
    | where ProcessCommandLine contains "steghide.exe"
    | project FileName, ProcessCommandLine
```
5.3 Query Results:
![image](https://github.com/stevenrim/threathunt1/blob/main/step4screenshot.png)

