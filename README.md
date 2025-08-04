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
Incident created in Sentinel<img width="972" height="301" alt="VM powershell stimulation" src="https://github.com/user-attachments/assets/009d730d-bf49-4228-b56c-d0b5da24c610" />

Alert fired in Defender
Attack linked to specific VM
Detection rule ran every 5 minutes
Full visibility, traceability, and response workflow achieved

Screenshots 📸
<img width="1727" height="591" alt="Sentinel Incident tab" src="https://github.com/user-attachments/assets/1a7628ca-2247-425a-bde7-de1d4a256d1a" />
<img width="957" height="780" alt="Analytical Rule" src="https://github.com/user-attachments/assets/17231e2a-2b38-4ec7-9a62-34b931dfd429" />
<img width="924" height="838" alt="Analytical Rule with MITRE Tagging" src="https://github.com/user-attachments/assets/60d8147c-5a0f-4040-a7b2-c9dc7041e157" />
<img width="1719" height="504" alt="VM " src="https://github.com/user-attachments/assets/c712f9da-2260-4fef-a171-d07bbb0da94c" />
![Uploading VM powershell stimulation.png…]()
<img width="1667" height="722" alt="KQL Detection Log Result" src="https://github.com/user-attachments/assets/21e03d7b-3d52-4440-aa39-71e8322b244a" />


Summary
This lab proves SOC Tier 1/2 skills in detection, hunting, and incident response using Microsoft’s security stack. Fully repeatable, validated, and publicly documented.

License
MIT — Free to use, fork, improve.

