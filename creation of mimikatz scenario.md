# Threat Event (Simulated Credential Dump via Mimikatz)

## Atomic Test T1003.001 (Dump LSASS Memory using mimikatz.exe)

This threat hunt is based on a simulated credential access attack using the Atomic Red Team framework to generate logs for detection.

---

## 🎯 Reason for the Hunt

Following recent cybersecurity alerts and red team engagements highlighting increased use of credential dumping tools like Mimikatz, the cybersecurity team has been tasked (via management directive) with validating our ability to detect and investigate memory dumping of `LSASS.exe`.  
This is a common step in lateral movement and privilege escalation attacks.

---

## 🧪 What the Atomic Test Does

This Atomic Red Team simulation for **T1003.001 - Dump LSASS Memory using Mimikatz** is designed to be safe for testing and log generation, without compromising the system:

- ✅ May create a dummy LSASS dump file (e.g., `lsass.dmp` or a placeholder file) to simulate malicious behavior.
- ✅ May launch a benign process with memory access flags typically used to access LSASS (e.g., `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION`).
- ✅ **Simulated Execution Only**: It does not extract real credentials but will generate telemetry logs (like process events, file creation, etc.) useful for hunting.
- ✅ Ideal for Detection Engineering and Training, without risk of actual compromise.

---

## 👨‍💻 Steps the "Bad Actor" Took (Log Generation via Atomic Red Team)

### 🧰 Step 1: Install Prerequisites (Run in PowerShell as Admin)

```powershell
# Install Git if not already installed
winget install --id Git.Git -e

# Install PowerShell module for Atomic Red Team
Install-Module -Name Invoke-AtomicRedTeam -Force

# Import the module
Import-Module Invoke-AtomicRedTeam
```

---

### 📦 Step 2: Download Atomic Red Team Repo and Tests

```powershell
# Clone the repo
git clone https://github.com/redcanaryco/atomic-red-team.git C:\AtomicRedTeam

# Set path to atomics folder
Set-AtomicRedTeamConfiguration -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

---

### 🚀 Step 3: Execute Atomic Test T1003.001-3 (Mimikatz Dump LSASS)

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 3
```
This test launches `mimikatz.exe` in a way that simulates LSASS memory access.  
Even if no real data is exfiltrated, it generates enough activity for log-based threat hunting.

---

## 📚 Tables Used to Detect IOCs:

| Table                  | Description                                      |
|-------------------------|--------------------------------------------------|
| DeviceProcessEvents     | Detects mimikatz execution and LSASS access simulation |
| DeviceFileEvents        | Detects creation of `.dmp` or similar dump files |
| DeviceEvents            | Captures Windows Defender or EDR alerts          |
| DeviceNetworkEvents     | (Optional) If Mimikatz attempts outbound connections |

---

## 🔍 Threat Hunting Queries (Microsoft Defender KQL)

### ✅ Detect Mimikatz Execution

```kql
DeviceProcessEvents
| where FileName =~ "mimikatz.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

---

### ✅ Detect Access to LSASS (from mimikatz or others)

```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("lsass", "sekurlsa")
| or ProcessCommandLine has "mimikatz"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

---

### ✅ Look for Dump File Creation

```kql
DeviceFileEvents
| where FileName endswith ".dmp"
| where FolderPath contains "lsass" or FileName contains "lsass"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```

---

### ✅ Check for Defender Detections (Mimikatz or Dumping)

```kql
DeviceEvents
| where ActionType has_any ("AntivirusDetection", "ThreatDetected")
| where AdditionalFields contains "mimikatz" or AdditionalFields contains "lsass"
| project Timestamp, DeviceName, ActionType, ReportId, AdditionalFields
```

---

## 🧩 Summary

This Atomic Red Team simulation safely mimics a **T1003.001 credential dumping attack** using `mimikatz.exe`, generating logs for threat hunting and detection testing.  
It's a great exercise to validate if your security tools can detect credential theft behavior without putting actual credentials at risk.

---

*Let me know if you'd like this turned into a Markdown file or a Defender Workbook to share with your team! 🚀*
