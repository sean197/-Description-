<img width="1667" height="722" alt="KQL Detection Log Result" src="https://github.com/user-attachments/assets/d8f9738a-b495-44d5-9da1-5a1667b87c9d" /># -Description-
Simulated attack detection using Microsoft Sentinel, Defender for Endpoint, and KQL. Incident triggered and detected from custom PowerShell persistence script.

Microsoft Sentinel Threat Detection Lab 🚨
Overview
Simulated a real-world attack using obfuscated PowerShell persistence. Detected it with a custom KQL rule in Microsoft Sentinel, triggered an incident in Defender for Endpoint, and validated full alert → incident flow.

Key Tools
Microsoft Sentinel
Defender for Endpoint (P2)
Azure VM (Windows 11)
KQL (Log & Hunting)
MITRE ATT&CK Mapping


Attack Script (Simulated Persistence)

Set-MpPreference -DisableRealtimeMonitoring $true

$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $registryPath -Name "Updater" `
-Value "powershell.exe -w hidden -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQA=" -Force

Start-Process powershell.exe -ArgumentList "-w hidden -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQA="

Set-MpPreference -DisableRealtimeMonitoring $false


Detection Query (KQL)
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Start-Sleep" and ProcessCommandLine contains "-enc"
| sort by Timestamp desc

MITRE ATT&CK Mapping
Execution → T1059.001 (PowerShell)
Persistence → T1547 (Registry Run Keys)

Outcome

Alert fired in Defender
Attack linked to specific VM
Detection rule ran every 5 minutes
Full visibility, traceability, and response workflow achieved

Screenshots 
Sentinel Incident
<img width="1727" height="591" alt="Sentinel Incident tab" src="https://github.com/user-attachments/assets/c7573854-94cd-4505-8ac7-5e674a18fb06" />

Defender Device Inventory
<img width="1719" height="504" alt="VM " src="https://github.com/user-attachments/assets/9fcb7fcd-85c9-4761-9343-ceef452f7fa0" />

VM PowerShell Simulation
<img width="972" height="301" alt="VM powershell stimulation" src="https://github.com/user-attachments/assets/6b5111c3-3921-403b-87c9-64821123e482" />

KQL Detection Log Result
<img width="1667" height="722" alt="KQL Detection Log Result" src="https://github.com/user-attachments/assets/c7713c09-2888-4604-a6ce-5aee9168da33" />

Analytics Rule w/ MITRE Tagging
<img width="924" height="838" alt="Analytical Rule with MITRE Tagging" src="https://github.com/user-attachments/assets/88de26ad-0faf-4c35-bea8-d4b87ae46ed9" />






Summary
This lab proves SOC Tier 1/2 skills in detection, hunting, and incident response using Microsoft’s security stack. Fully repeatable, validated, and publicly documented.

License
MIT — Free to use, fork, improve.

