# Threat Hunt Report — Akira Ransomware
## Ashford Sterling Recruitment

| | |
|---|---|
| **Analyst** | Terrance Fortson |
| **Date** | March 15, 2026 |
| **Difficulty** | Advanced |
| **Platform** | Microsoft Defender for Endpoint + Microsoft Sentinel (KQL) |
| **Environment** | `as-pc1` · `as-pc2` · `as-srv` |
| **Preceded By** | The BROKER — Ashford Sterling Recruitment |

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Environment](#environment)
- [IOC Reference](#ioc-reference)
  - [Domains & IPs](#domains--ips)
  - [Files & Hashes](#files--hashes)
  - [Accounts & Identifiers](#accounts--identifiers)
- [Attack Chain](#attack-chain)
  - [1. Initial Access — Pre-staged Persistence](#1-initial-access--pre-staged-persistence)
  - [2. Reconnaissance](#2-reconnaissance)
  - [3. C2 Beacon Deployment](#3-c2-beacon-deployment)
  - [4. Defense Evasion](#4-defense-evasion)
  - [5. Credential Theft](#5-credential-theft)
  - [6. Lateral Movement](#6-lateral-movement)
  - [7. Exfiltration](#7-exfiltration)
  - [8. Ransomware Deployment](#8-ransomware-deployment)
- [Attack Timeline](#attack-timeline)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Remediation Recommendations](#remediation-recommendations)
- [Lessons Learned](#lessons-learned)

---

## Executive Summary

On January 27, 2026, a ransomware affiliate returned to the Ashford Sterling Recruitment network using access pre-staged during a prior intrusion (The BROKER). Leveraging a dormant AnyDesk backdoor and a re-enabled user account left unremediated, the attacker deployed Akira ransomware across two hosts, exfiltrated sensitive company data, and issued a ransom demand of £65,000. The attack was entirely preventable — every capability used on January 27 was established twelve days earlier and never cleaned up.

---

## Environment

| Hostname | IP Address | Role | Compromised |
|----------|-----------|------|-------------|
| `as-pc1` | `10.1.0.154` | Workstation | AnyDesk persistence only |
| `as-pc2` | `10.1.0.183` | Workstation — primary attack host | ✅ Yes |
| `as-srv` | `10.1.0.203` | File server | ✅ Yes |

---

## IOC Reference

### Domains & IPs

| Indicator | Type | Description |
|-----------|------|-------------|
| `sync.cloud-endpoint.net` | Domain | Payload delivery |
| `cdn.cloud-endpoint.net` | Domain | C2 communications |
| `cloud-endpoint.net` | Domain | Attacker root domain — block entire domain |
| `104.21.30.237` | IP | C2 IP (Cloudflare-proxied) |
| `172.67.174.46` | IP | C2 IP (Cloudflare-proxied) |
| `88.97.164.155` | IP | Attacker external IP |
| `relay-0b975d23.net.anydesk.com` | Domain | AnyDesk relay — as-srv |
| `akiral2iz6a7qgd3ayp316yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | TOR | Akira negotiation portal |

### Files & Hashes

| Filename | SHA256 | Description |
|----------|--------|-------------|
| `wsync.exe` (v1) | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` | Original C2 beacon |
| `wsync.exe` (v2) | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` | Replacement — Akira ransomware on as-pc2 |
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` | Akira ransomware on as-srv |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` | Defender killer script |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` | Advanced IP Scanner installer |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` | Data staging/compression tool |
| `AnyDesk.exe` | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` | Pre-staged RAT (from The BROKER) |

### Accounts & Identifiers

| Indicator | Type | Description |
|-----------|------|-------------|
| `david.mitchell` | Account | Compromised local account — as-pc2 |
| `as.srv.administrator` | Account | Compromised local admin — as-srv |
| `813R-QWJM-XKIJ` | Victim ID | Akira negotiation portal ID |

---

## Attack Chain

### 1. Initial Access — Pre-staged Persistence

The attacker re-entered the environment via **AnyDesk**, deployed to `C:\Users\Public\AnyDesk.exe` across all three hosts during The BROKER and never remediated. The attacker's external IP `88.97.164.155` connected to all three hosts before concentrating activity on `as-pc2` under the compromised `david.mitchell` account.

**Key Findings**
- AnyDesk executing from `C:\Users\Public\` — not a legitimate install path
- Attacker IP `88.97.164.155` connected to `as-pc1`, `as-pc2`, and `as-srv` via AnyDesk
- `david.mitchell` — a previously disabled account re-enabled during The BROKER — used as primary identity
- `as.srv.administrator` authenticated to `as-srv` via RDP from `10.0.8.9` (Guacamole relay)

**Queries**

```kql
-- AnyDesk execution path
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where FileName =~ "AnyDesk.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| limit 20
```

**Evidence**

<img width="1013" height="522" alt="Image" src="https://github.com/user-attachments/assets/439721c5-645b-4281-80d5-5cb301a72f12" />

*AnyDesk.exe executing from `C:\Users\Public\` on as-pc2 — a non-standard installation path indicating the attacker manually placed the binary here during The BROKER. Legitimate AnyDesk installations use `C:\Program Files (x86)\AnyDesk\`.*

---

```kql
-- Attacker IP connections across all hosts
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where RemoteIP == "88.97.164.155"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, RemotePort
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1348" height="527" alt="Image" src="https://github.com/user-attachments/assets/543a89d2-e5de-4b50-a2e3-f1081b5aa58d" />

*External IP `88.97.164.155` connecting to all three hosts (`as-pc1`, `as-pc2`, `as-srv`) via `AnyDesk.exe` — confirming the attacker had full environment access from a single external IP using pre-staged backdoors.*

---

```kql
-- Compromised account logons
DeviceLogonEvents
| where DeviceName contains "AS-PC2"
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType contains "LogonSuccess"
| where AccountDomain contains "as-pc2"
```

**Evidence**

<img width="1673" height="525" alt="Image" src="https://github.com/user-attachments/assets/5205d1e7-6676-495f-832a-2ad24810a80c" />

*`david.mitchell` successfully authenticating to `as-pc2` multiple times throughout the attack window. This account was disabled prior to The BROKER and re-enabled by the attacker to avoid creating new suspicious accounts.*

---

### 2. Reconnaissance

Network reconnaissance was performed using **Advanced IP Scanner** (`scan.exe`). The tool was first downloaded via `bitsadmin.exe` — a LOLBin that failed across multiple staging paths before the attacker fell back to PowerShell's `Invoke-WebRequest`. The scanner ran in portable mode, leaving no installation footprint.

**Key Findings**
- `bitsadmin.exe` attempted downloads to `C:\Temp\`, `C:\Users\Public\`, and `C:\Users\david.mitchell\Downloads\` before succeeding
- `scan.exe` is an installer wrapper — actual scanner is `advanced_ip_scanner.exe`
- Executed with `/portable` flag — no registry entries, no installation artifacts
- Full process chain: `powershell.exe` → `scan.exe` → `scan.tmp` → `advanced_ip_scanner.exe`
- Subnet `10.1.0.x` probed; hosts `10.1.0.154` (`as-pc1`) and `10.1.0.183` (`as-pc2`) enumerated

**Queries**

```kql
-- Full scanner process chain
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T20:17:00Z) .. datetime(2026-01-27T20:45:00Z))
| where DeviceName =~ "AS-PC2"
| where InitiatingProcessFileName has_any ("scan", "advanced")
    or FileName has_any ("scan", "advanced")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 20
```

**Evidence**

<img width="1631" height="317" alt="Image" src="https://github.com/user-attachments/assets/56725a5d-06d6-411a-9f2b-1bef8d20ec2c" />

*Full process chain: `powershell.exe` → `scan.exe` → `scan.tmp` → `advanced_ip_scanner.exe`. The `/portable` flag runs the scanner with no installation footprint — no registry entries, no Start Menu entry, easily deleted after use.*

---

```kql
-- bitsadmin download attempts
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where ProcessCommandLine has_any ("scan", "ip", "network")
    or FileName has "scan"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 20
```

**Evidence**

<img width="1626" height="427" alt="Image" src="https://github.com/user-attachments/assets/aab6fabb-f419-4116-9308-4e1d1e696862" />

*`bitsadmin.exe` attempting to download `scan.exe` to multiple staging paths before succeeding. The final row shows `wsync.exe` using the same LOLBin to download `kill.bat` from `sync.cloud-endpoint.net` — confirming the C2 domain was used for both tool delivery and payload staging.*

---

### 3. C2 Beacon Deployment

The pre-staged `RuntimeBroker.exe` beacon from The BROKER had unstable C2 communications. The attacker deployed `wsync.exe` as a replacement, downloading it from `sync.cloud-endpoint.net` using three distinct obfuscation techniques to evade content inspection. The first version was replaced after confirming C2 stability.

**Key Findings**
- Three download obfuscation methods used: direct URL, Base64-encoded URL, string concatenation
- First beacon (v1) deployed at `20:22:50` UTC — unstable, replaced
- Replacement beacon (v2) deployed at `20:44:32` UTC via `FileModified` event — overwrote v1
- `wsync.exe` masquerades as a Windows file sync utility
- Staged to `C:\ProgramData\wsync.exe`

**Queries**

```kql
-- Original beacon creation
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where FileName =~ "wsync.exe"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
| limit 10
```

**Evidence**

<img width="1527" height="370" alt="Image" src="https://github.com/user-attachments/assets/47cb7df2-7b14-47d6-8770-01312bf21cfa" />

*`wsync.exe` first created at `20:22:50` UTC with SHA256 `66b876c52946...` — the original unstable beacon staged to `C:\ProgramData\` via PowerShell. The second row shows the replacement at `20:44:07` with no SHA256, logged as a FileModified event.*

---

```kql
-- Replacement beacon (FileModified = overwrite)
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where FileName =~ "wsync.exe"
| where ActionType == "FileModified"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
| limit 10
```

**Evidence**

<img width="1532" height="340" alt="Image" src="https://github.com/user-attachments/assets/0a8f4eab-8a8d-412c-89ca-675b1ed0579c" />

*`wsync.exe` overwritten at `20:44:32` UTC with the final Akira ransomware binary — SHA256 `0072ca0d0adc...`. The `FileModified` action type confirms this was an overwrite of the original beacon rather than a new file creation.*

---

```kql
-- C2 network connections
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T23:59:00Z))
| where DeviceName =~ "AS-PC2"
| where RemoteUrl has "cloud-endpoint"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Evidence**

<img width="1232" height="477" alt="Image" src="https://github.com/user-attachments/assets/8151c81f-fe28-4dcf-a4ed-d1f4c560840e" />

*`sync.cloud-endpoint.net` resolving to both Cloudflare-proxied IPs throughout the attack window. The final two rows show `wsync.exe` making C2 callbacks post-execution — confirming the ransomware binary actively communicated with attacker infrastructure after deployment.*

---

### 4. Defense Evasion

Before encrypting, `wsync.exe` dropped `kill.bat` and executed it via `cmd.exe`. The script systematically disabled Windows Defender through PowerShell and permanently modified the registry to prevent re-enabling. Volume shadow copies were then deleted to prevent file recovery.

**Key Findings**
- `wsync.exe` spawned `cmd.exe /c C:\ProgramData\kill.bat` at `21:03:36` UTC
- Defender disabled: `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`, `DisableScriptScanning`
- Registry permanently modified: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` = `1` at `21:03:42` UTC
- Shadow copies deleted: `vssadmin delete shadows /all /quiet` and `wmic shadowcopy delete` at `21:09:10` UTC
- `clean.bat` dropped post-encryption to delete ransomware binary — anti-forensics

**Queries**

```kql
-- kill.bat execution discovery
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T21:03:00Z) .. datetime(2026-01-27T21:04:00Z))
| where DeviceName =~ "AS-PC2"
| where FileName =~ "cmd.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 20
```

**Evidence**

<img width="1271" height="452" alt="Image" src="https://github.com/user-attachments/assets/05102b7e-e49f-4b50-b7cf-e034df641a9c" />

*`wsync.exe` spawning `cmd.exe /c C:\ProgramData\kill.bat` at `21:03:36` UTC — confirming the ransomware binary was directly responsible for dropping and executing the defense evasion script.*

---

```kql
-- Defender disable commands
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableAntiSpyware", "Set-MpPreference")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 50
```

**Evidence**

<img width="1592" height="585" alt="Image" src="https://github.com/user-attachments/assets/c88e5349-ebe0-46b6-a823-ecd8cbc7cd4b" />

*`kill.bat` systematically disabling Windows Defender through multiple `Set-MpPreference` commands via PowerShell. The two highlighted `reg.exe` rows represent permanent registry-level modifications — more durable than the PowerShell preference changes and not reversible without manual intervention.*

---

```kql
-- Registry tampering
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-27T21:00:00Z) .. datetime(2026-01-27T21:10:00Z))
| where DeviceName =~ "AS-PC2"
| where RegistryKey has "Windows Defender"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| limit 20
```

**Evidence**

<img width="1700" height="558" alt="Image" src="https://github.com/user-attachments/assets/47b7c9d6-9e80-41e0-be64-1e34d2d8e1b4" />

*`DisableAntiSpyware` registry value set to `1` at `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender` at `21:03:42` UTC — permanently disabling Windows Defender at the Group Policy layer via `reg.exe`.*

---

```kql
-- Shadow copy deletion
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("as-pc2", "as-srv")
| where ProcessCommandLine has_any ("shadow", "vssadmin", "wmic", "backup")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1322" height="388" alt="Image" src="https://github.com/user-attachments/assets/749b54ce-c90b-4812-89e2-e085717acbc6" />

*Two shadow copy deletion methods executed in sequence at `21:09:10` UTC — `vssadmin delete shadows /all /quiet` and `wmic shadowcopy delete`. Both initiated by `wsync.exe` via `cmd.exe`, eliminating all native Windows recovery points before encryption began.*

---

### 5. Credential Theft

After disabling Defender, `wsync.exe` enumerated running processes to confirm LSASS was active, accessed the LSASS named pipe, and dumped LSASS memory to harvest credentials for lateral movement.

**Key Findings**
- Process enumeration: `cmd.exe /c "tasklist | findstr Lsass"` — initiated by `wsync.exe`
- Named pipe `\Device\NamedPipe\lsass` accessed at `21:42:56` UTC
- LSASS memory read at `21:45:38` UTC — 201 reads, 25KB copied

**Queries**

```kql
-- Process enumeration for LSASS
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-27T21:30:00Z))
| where DeviceName =~ "AS-PC2"
| where ProcessCommandLine has_any ("Get-Process", "tasklist", "ps")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 20
```

**Evidence**

<img width="1288" height="382" alt="Image" src="https://github.com/user-attachments/assets/503e8c1c-0045-40fd-b5c3-ce9d1820d0cf" />

*`cmd.exe /c "tasklist | findstr lsass"` executed twice by `wsync.exe` — confirming LSASS was running before initiating the memory dump. The case-sensitive `findstr Lsass` usage reflects operator familiarity with Windows process naming conventions.*

---

```kql
-- Named pipe access
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T21:00:00Z) .. datetime(2026-01-27T22:00:00Z))
| where DeviceName =~ "AS-PC2"
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has "lsass"
| where InitiatingProcessFileName != "lsass.exe"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, AdditionalFields
| limit 20
```

**Evidence**

<img width="1692" height="432" alt="Image" src="https://github.com/user-attachments/assets/270ac27a-247d-4047-b641-5bc323b85cd4" />

*`\Device\NamedPipe\lsass` accessed at `21:42:56` UTC by a non-LSASS process as a Client — the standard precursor to an LSASS memory dump. The LSASS memory read followed three minutes later at `21:45:38` UTC capturing 25KB of credential material across 201 reads.*

---

### 6. Lateral Movement

Using credentials obtained from the LSASS dump, the attacker authenticated to `as-srv` as `as.srv.administrator` via RDP through the Guacamole relay. `david.mitchell` also authenticated to `as-srv` from `as-pc2` via a Network logon.

**Key Findings**
- `as.srv.administrator` — RemoteInteractive logon (RDP Type 10) from `10.0.8.9` at `19:22:06` UTC
- `david.mitchell` — Network logon from `10.1.0.183` (`as-pc2`) at `20:18:42` UTC
- Source `10.0.8.9` is in the Guacamole relay subnet — consistent with attacker routing

**Query**

```kql
-- Logon events on as-srv
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "as-srv"
| where ActionType == "LogonSuccess"
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "")
| project TimeGenerated, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1376" height="555" alt="Image" src="https://github.com/user-attachments/assets/0ac0949b-bd6b-4fe9-8ebd-31bdcadc005b" />

*`as.srv.administrator` authenticating to `as-srv` via RemoteInteractive (RDP) from `10.0.8.9` — the Guacamole relay subnet. `david.mitchell` subsequently authenticating via Network logon from `10.1.0.183` (as-pc2) — both compromised accounts used to establish full control of the file server.*

---

### 7. Exfiltration

Prior to encryption, sensitive company data was compressed using `st.exe` and archived as `exfil_data.zip` at `C:\Users\Public\` on `as-srv`. Akira's ransom note claimed exfiltration of financial documents, employee data, client databases, and proprietary business information.

**Key Findings**
- `st.exe` deployed to `C:\ProgramData\st.exe` on `as-srv` via PowerShell
- `exfil_data.zip` created at `C:\Users\Public\exfil_data.zip` at `22:24:09` UTC
- Archive created after encryption began — data collected earlier in the session

**Query**

```kql
-- Exfil archive creation
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("as-srv", "as-pc2")
| where FileName endswith ".zip"
    or FileName endswith ".7z"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1305" height="556" alt="Image" src="https://github.com/user-attachments/assets/26f25cdd-2920-47ca-8320-8dbc0f15c34a" />

*`st.exe` creating `exfil_data.zip` at `C:\Users\Public\exfil_data.zip` on `as-srv` at `22:24:09` UTC — six minutes after encryption began. The `C:\Users\Public\` staging location was used consistently across both investigations as a shared, writable directory accessible to any local account.*

---

### 8. Ransomware Deployment

Ransomware was deployed separately on each host. `wsync.exe` encrypted `as-pc2`. On `as-srv`, two failed `wsync.exe` execution attempts prompted the attacker to deploy a secondary binary, `updater.exe`, disguised as a Google Updater process. Ransom notes were dropped immediately upon encryption start. `clean.bat` deleted the ransomware binary two minutes after encryption began.

**Key Findings**
- `as-pc2`: `wsync.exe` — Akira ransomware, SHA256: `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`
- `as-srv`: `updater.exe` — Akira ransomware, SHA256: `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`
- `updater.exe` deployed at `22:18:29` UTC — staged by `powershell.exe`
- Ransom notes dropped at `22:18:33` UTC to Desktop, Documents, Downloads of `AS.SRV.Administrator`
- `.akira` extension appended to all encrypted files
- `clean.bat` executed at `22:20:27` UTC — deleted ransomware binary post-encryption

**Queries**

```kql
-- Ransomware process chain on as-srv
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("as-srv", "as-pc2", "as-pc1")
| where InitiatingProcessFileName in~ ("wsync.exe", "st.exe", "cmd.exe", "powershell.exe")
| where FolderPath has_any ("ProgramData", "Public", "Temp", "Downloads")
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1537" height="573" alt="Image" src="https://github.com/user-attachments/assets/6e6b4a59-462d-431b-829c-2d42b48e75c0" />

*`updater.exe` executed from `C:\ProgramData\` on `as-srv` at `22:18:29` UTC, staged by `powershell.exe`. The binary masquerades as a legitimate Google Updater process — deployed after two failed `wsync.exe` execution attempts on the file server.*

---

```kql
-- Ransom note drop
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("as-pc2", "as-srv")
| where FileName has "akira"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1612" height="421" alt="Image" src="https://github.com/user-attachments/assets/03f1472e-8edb-4053-84f3-e52b69371ce4" />

*Three `akira_readme.txt` ransom notes dropped simultaneously at `22:18:33` UTC by `updater.exe` across the Desktop, Documents, and Downloads directories of `AS.SRV.Administrator` — marking the confirmed start of encryption on `as-srv`.*

---

```kql
-- Cleanup script
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27T22:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName in~ ("as-pc2", "as-srv")
| where FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
| limit 20
```

**Evidence**

<img width="1300" height="463" alt="Image" src="https://github.com/user-attachments/assets/6a186fa9-b935-4f40-9eb5-c92d51c1d576" />

*`clean.bat` created at `C:\ProgramData\clean.bat` on `as-srv` at `22:20:27` UTC by `powershell.exe` — two minutes after encryption began. Designed to delete the ransomware binary post-execution, removing the primary forensic artifact from disk.*

---

## Attack Timeline

| Time (UTC) | Host | Event |
|-----------|------|-------|
| 19:10:24 | as-pc1 | Attacker connects via AnyDesk from `88.97.164.155` |
| 19:20:48 | as-pc2 | Attacker pivots to as-pc2 via AnyDesk |
| 19:22:06 | as-srv | `as.srv.administrator` RDP logon from `10.0.8.9` |
| 20:14:03 | as-pc2 | `bitsadmin.exe` attempts to download `scan.exe` — fails |
| 20:17:45 | as-pc2 | `advanced_ip_scanner.exe` executed in portable mode |
| 20:18:42 | as-srv | `david.mitchell` Network logon from as-pc2 |
| 20:22:50 | as-pc2 | `wsync.exe` v1 staged at `C:\ProgramData\` |
| 20:44:32 | as-pc2 | `wsync.exe` replaced with v2 (Akira payload) |
| 21:03:36 | as-pc2 | `kill.bat` executed — Defender disabled |
| 21:03:42 | as-pc2 | Registry modified: `DisableAntiSpyware` = 1 |
| 21:09:10 | as-pc2 | Shadow copies deleted |
| 21:42:56 | as-pc2 | `\Device\NamedPipe\lsass` accessed |
| 21:45:38 | as-pc2 | LSASS memory dumped — 201 reads, 25KB |
| 22:15:17 | as-srv | `wsync.exe` execution fails on as-srv (x2) |
| 22:18:29 | as-srv | `updater.exe` deployed and executed |
| 22:18:33 | as-srv | Ransom notes dropped — encryption begins |
| 22:20:27 | as-srv | `clean.bat` deletes ransomware binary |
| 22:24:09 | as-srv | `exfil_data.zip` created by `st.exe` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1078 | Valid Accounts — `david.mitchell` |
| Execution | T1059.001 | PowerShell |
| Execution | T1059.003 | Windows Command Shell |
| Persistence | T1219 | Remote Access Software — AnyDesk |
| Defense Evasion | T1036.005 | Masquerading — `wsync.exe`, `updater.exe` |
| Defense Evasion | T1027 | Obfuscated Files or Information — Base64/string concat downloads |
| Defense Evasion | T1562.001 | Disable or Modify Tools — `kill.bat` |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion — `clean.bat` |
| Defense Evasion | T1197 | BITS Jobs — `bitsadmin.exe` |
| Credential Access | T1003.001 | LSASS Memory Dump |
| Discovery | T1057 | Process Discovery — `tasklist \| findstr Lsass` |
| Discovery | T1046 | Network Service Discovery — Advanced IP Scanner |
| Lateral Movement | T1021.001 | Remote Desktop Protocol |
| Collection | T1560.001 | Archive Collected Data — `st.exe` / `exfil_data.zip` |
| Command and Control | T1219 | Remote Access Software — AnyDesk |
| Command and Control | T1105 | Ingress Tool Transfer |
| Command and Control | T1090.002 | External Proxy — Cloudflare |
| Impact | T1486 | Data Encrypted for Impact |
| Impact | T1490 | Inhibit System Recovery — shadow copy deletion |

---

## Remediation Recommendations

| Priority | Action |
|----------|--------|
| 🔴 Critical | Reimage `as-pc2` and `as-srv` — do not attempt in-place recovery |
| 🔴 Critical | Remove AnyDesk from all hosts — treat any instance with password `intrud3r!` as a live backdoor |
| 🔴 Critical | Disable and delete `david.mitchell`, `svc_backup`, and `as.srv.administrator` |
| 🔴 Critical | Block `cloud-endpoint.net` (entire domain) at DNS, proxy, and firewall |
| 🔴 Critical | Block `88.97.164.155` at perimeter firewall |
| 🟠 High | Rotate all credentials on affected hosts — assume full compromise |
| 🟠 High | Implement LAPS to eliminate shared local admin passwords |
| 🟠 High | Restrict RDP to approved jump hosts — block peer-to-peer RDP via GPO |
| 🟠 High | Implement off-host immutable backups — shadow copies alone are insufficient |
| 🟡 Medium | Alert on `Set-MpPreference` disabling Defender protections |
| 🟡 Medium | Alert on `vssadmin delete shadows` by non-backup processes |
| 🟡 Medium | Alert on executables running from `C:\Users\Public\` or `C:\ProgramData\` with no known association |
| 🟡 Medium | Alert on `bitsadmin.exe` downloading executables from external URLs |
| 🟡 Medium | Block unapproved commercial RATs (AnyDesk, TeamViewer) via application control |

---

## Lessons Learned

The most challenging part of this investigation was not understanding the attack, it was learning to ask the right questions of the data. Knowing that `kill.bat` disabled Defender is one thing. Writing a query that surfaces that finding without already knowing the filename is something else entirely. Early on I found myself with a clear picture of what I was looking for but uncertain how to translate that into KQL that would actually return results. Columns were not always what I expected, time windows needed adjustment, and queries that should have worked came back empty. Working through that gap between knowing what happened and knowing how to prove it in telemetry was where most of the real learning happened.

The methodology that made the biggest difference was hunting behavior first and artifacts second. When looking for `kill.bat`, the right starting point was the `Set-MpPreference` commands disabling Defender, not the filename itself. Following that chain backward through the initiating process to `cmd.exe` and then to what `cmd.exe` was executing revealed the filename organically. That approach of letting each finding generate the next question is reusable across any investigation regardless of what tools the attacker used.

The cross-investigation dependency was the sharpest operational lesson. Several findings in this investigation could not be resolved from the telemetry alone without knowledge of The BROKER. The staging domain, the AnyDesk deployment, the `david.mitchell` account, and the `cloud-endpoint.net` infrastructure all required connecting evidence across two incidents separated by twelve days. If those IOCs had not been available, significant portions of the attack chain would have been harder to explain. Threat actors reuse infrastructure and access. Investigations that close without complete documentation leave the next analyst, or the next incident, starting from scratch.

Mapping the environment early is something I would prioritize differently next time. Hostname to IP assignments were assumed incorrectly at several points during the investigation, which sent queries in the wrong direction before `DeviceNetworkInfo` corrected the picture. Running an environment mapping query at the start of any investigation before touching anything else is now a fixed first step.

---

*This report was produced as part of a controlled scenario provided by SancLogic. All systems, users, files, and IP addresses are simulated.*
