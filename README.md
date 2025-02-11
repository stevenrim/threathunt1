(Disclaimer: This article presents a fictional threat hunting scenario created for educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat hunting skills, analytical thinking, and investigative processes for professional development. It does not reflect any actual security incidents or breaches.)

# Threat Hunt Report: Bryce Montgomery
## Platforms Used
- EDR: Microsoft Defender
- Query Language: KQL (Kusto Query Language)
## Scenario
The Risk Department of a large tech company has raised concerns regarding Bryce Montgomery, a company executive, who is suspected of unauthorized access or theft of intellectual property. Given Montgomery’s executive privileges, he has full administrative access to his workstation (corp-ny-it-0334), allowing him to bypass certain security controls. Additionally, due to a Data Loss Prevention (DLP) exception for executives, standard monitoring and restrictions on file transfers do not apply, increasing the risk of potential data exfiltration.
To address these concerns, I was tasked to investigate Bryce Montgomery's computer for any signs of unusual activity or potential data theft.
## Steps Taken
1.0 Known Information
- Username: bmontgomery
- Workstation: corp-ny-it-0334

1.1 Identify the “thumbprint” (any type) of one of the first corporate files that was accessed or interacted with by Bryce Montgomery during the investigation.

1.2 Identified SHA256 hash of accessed files with the following query:
```kql
DeviceFileEvents
| where DeviceName == "corp-ny-it-0334" 
| where InitiatingProcessAccountName == "bmontgomery"
| where ActionType in ("FileModified", "FileCopied", "FileAccessed")
| project Timestamp, DeviceId, ActionType, FileName, SHA256  
| order by Timestamp asc
```
1.1 Query results:
