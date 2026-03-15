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

```kql
-- Attacker IP connections across all hosts
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where RemoteIP == "88.97.164.155"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, RemotePort
| order by TimeGenerated asc
| limit 20
```

```kql
-- Compromised account logons
DeviceLogonEvents
| where DeviceName contains "AS-PC2"
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType contains "LogonSuccess"
| where AccountDomain contains "as-pc2"
```

> **Evidence:** *(screenshot — AnyDesk process from C:\Users\Public\)*

> **Evidence:** *(screenshot — 88.97.164.155 connections across all three hosts)*

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

> **Evidence:** *(screenshot — advanced_ip_scanner.exe execution with /portable arguments)*

> **Evidence:** *(screenshot — bitsadmin download attempts)*

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

```kql
-- C2 network connections
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T23:59:00Z))
| where DeviceName =~ "AS-PC2"
| where RemoteUrl has "cloud-endpoint"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by TimeGenerated asc
```

> **Evidence:** *(screenshot — wsync.exe FileCreated and FileModified events with hashes)*

> **Evidence:** *(screenshot — cloud-endpoint.net C2 connections)*

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

```kql
-- Defender disable commands
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where DeviceName =~ "AS-PC2"
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableAntiSpyware", "Set-MpPreference")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| limit 50
```

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

> **Evidence:** *(screenshot — cmd.exe /c kill.bat initiated by wsync.exe)*

> **Evidence:** *(screenshot — Set-MpPreference commands)*

> **Evidence:** *(screenshot — DisableAntiSpyware registry modification)*

> **Evidence:** *(screenshot — vssadmin delete shadows)*

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

```kql
-- Named pipe access
DeviceEvents
| where TimeGenerated between (datetime(2026-01-27T21:40:00Z) .. datetime(2026-01-27T21:50:00Z))
| where DeviceName =~ "AS-PC2"
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName in~ ("wsync.exe", "powershell.exe", "rundll32.exe", "cmd.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, AdditionalFields
| limit 20
```

> **Evidence:** *(screenshot — tasklist | findstr Lsass command)*

> **Evidence:** *(screenshot — \Device\NamedPipe\lsass access event)*

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

> **Evidence:** *(screenshot — as.srv.administrator and david.mitchell logon events on as-srv)*

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

> **Evidence:** *(screenshot — exfil_data.zip created by st.exe)*

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

> **Evidence:** *(screenshot — updater.exe deployed by powershell.exe on as-srv)*

> **Evidence:** *(screenshot — akira_readme.txt dropped at 22:18:33)*

> **Evidence:** *(screenshot — clean.bat at 22:20:27)*

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

*This report was produced as part of a controlled Cyber Range scenario provided by SancLogic. All systems, users, files, and IP addresses are simulated.*
