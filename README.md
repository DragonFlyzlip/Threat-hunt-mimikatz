# Threat Event (Simulated Credential Dump via Mimikatz)

## Atomic Test T1003.001 (Dump LSASS Memory using mimikatz.exe)

This threat hunt is based on a simulated credential access attack using the Atomic Red Team framework to generate logs for detection.

---

## Scenario:
**Suspicious Admin Behavior on Finance Server Triggers Credential Dumping Hunt**

Last week, a routine audit of system activity revealed unusual command-line behavior on a critical finance server. A privileged admin account was observed spawning PowerShell instances with obfuscated arguments and accessing memory-intensive system processes. While no malware was detected, the activity closely resembled known behaviors associated with credential dumping tools such as Mimikatz—especially targeting `lsass.exe`.

To simulate this safely and generate the necessary telemetry, the SOC team used Atomic Red Team’s T1003.001 test using Mimikatz, targeting a non-production Windows 10 VM.

---

## Step 1 – Initial PowerShell Command

At **11:40 PM on April 23rd**, I noticed a suspicious PowerShell command being executed on the system. It was running `createdump.exe`, which is typically used for crash dumps, but this time it was being repurposed to dump LSASS memory.  
The dump was saved in the Temp folder — definitely a red flag.  
I knew this was an attempt to extract credential data.

---

## Step 2 – Second PowerShell Command

At **11:40:13 PM**, another command was executed by the same user (**ash**).  
This time it was using `xordump.exe`, another tool that can be leveraged for dumping LSASS memory.  
The file was saved in Temp, confirming the attacker’s intent was to extract sensitive information again.

---

## Step 3 – Windows Defender Detection

While investigating, I saw that Windows Defender had already detected and blocked the attempt.  
The detection was flagged as **HackTool:PowerShell/Lsassdump.A**, matching what I was seeing — a classic LSASS memory dump technique used by attackers to harvest credentials.  
Defender successfully blocked the action before it could succeed.

---

## Step 4 – Third Attempt with rdrleakdiag.exe

At **12:07 AM on April 24th**, the attacker tried again—this time with `rdrleakdiag.exe`.  
The command targeted LSASS memory and dumped it into a new folder in Temp.  
It was clear the attacker was trying different tools to bypass detection and still extract credentials.

---

## Step 5 – Mimikatz Detected

At **12:11 AM**, Windows Defender flagged and blocked another attack, this time **Mimikatz**, one of the most infamous credential-dumping tools.  
The detection came in as **HackTool:PowerShell/Mimikatz!ams**.  
Seeing Mimikatz on the system was a big indicator that someone was trying to steal credentials.  
Thankfully, Defender stepped in and blocked it.

---

## Step 6 – Persistence with LSASSdump

At **12:15 AM**, I saw **ash** trying the LSASS dump technique again with the same tool flagged earlier (**HackTool:PowerShell/Lsassdump.A**).  
Attackers often try multiple times to break into a system, especially after being blocked.  
Defender once again blocked the action.

---

## Step 7 – Final Attempt

At **12:25 AM**, the final attempt occurred, involving running `createdump.exe` once more.  
The attacker seemed determined to get those LSASS credentials but was successfully blocked by the system’s defenses each time.

---

## KQL Queries Used:

```kql
DeviceProcessEvents
| where DeviceName == "ashj-atomictest"
| where FileName in~ ("rundll32.exe", "powershell.exe", "cmd.exe", "mimikatz.exe", "procdump.exe", "taskmgr.exe")
| where ProcessCommandLine has_any("lsass", "dump", "--write", "sekurlsa", "privilege::debug")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, ReportId
```
![image](https://github.com/user-attachments/assets/33d1d52c-a38a-4670-a7f3-e34ecf510ab9)

![image](https://github.com/user-attachments/assets/51cd7ca5-8e33-46cf-948b-51e699b22989)



```kql
DeviceProcessEvents
| where DeviceName == "ashj-atomictest"
| where FileName in~ ("rdrleakdiag.exe", "powershell.exe", "cmd.exe", "mimikatz.exe", "procdump.exe", "taskmgr.exe")
| where ProcessCommandLine has_any("lsass", "dump", "--write", "rdrleakdiag.exe", "privilege::debug")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, ReportId
```

![image](https://github.com/user-attachments/assets/e1820642-430b-45ea-9444-7ffbe09b5b0c)

```kql
DeviceEvents
| where ActionType has_any ("AntivirusDetection", "ThreatDetected")
| where AdditionalFields contains "mimikatz" or AdditionalFields contains "lsass"
| project Timestamp, DeviceName, ActionType, ReportId, AdditionalFields
```
  ![image](https://github.com/user-attachments/assets/e0ab27ef-2b26-454b-b78a-8b074af069ba)

![image](https://github.com/user-attachments/assets/8cbca49b-ec2d-46f0-886f-52672872cd1f)

---

## Conclusion

As the threat hunter, I observed a series of repeated and persistent attempts to dump LSASS memory — a known technique for credential harvesting.  
The attacker used multiple tools, including `createdump.exe`, `xordump.exe`, and **Mimikatz**, all in attempts to steal sensitive login credentials.  
However, Windows Defender successfully detected and blocked each attempt, preventing the attacker from extracting any valuable information.  

The persistence of the attacks was concerning, but the security measures held strong, and no damage was done.  
It’s a great example of how continuous monitoring and active defense work together to stop credential-stealing efforts.

---
