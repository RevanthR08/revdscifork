// =============================================================================
// MOCK DATA — Derived from 10 Windows SOC Event Log CSV Datasets
// All 10 datasets share the same schema:
//   timestamp, event_id, level, source, computer, user, opcode,
//   task_category, process_id, process_name, detail, cpu_usage,
//   mem_usage, network_io, integrity_level, is_signed, label
//
// Each dataset: 10,000 rows | 9,970 normal | 30 suspicious
// Threat events: powershell.exe "Encoded IEX Download", event_id 4688
// User-uploaded CSVs are matched to their enriched JSON companion files.
// =============================================================================

// ─── USER JSON DATASETS (user001logs.json, user002logs.json, …) ──────────────
// This map links an uploaded CSV filename (e.g. "user001logs.csv") to the
// scan_id that will be returned after the upload, so the UI can navigate
// directly to the rich, pre-computed analysis stored below.
export const USER_CSV_TO_SCAN_ID: Record<string, string> = {
  "user001logs.csv": "user-001",
  "user002logs.csv": "user-002",
  "user003logs.csv": "user-003",
}

// Detection type labels shown in the pie chart
export const DETECTION_TYPE_LABELS: Record<string, string> = {
  rule:               "Rule-Based",
  ml_anomaly:         "ML Anomaly",
  behavioral:         "Behavioral",
  yara_match:         "YARA Match",
  heuristic:          "Heuristic",
  impossible_travel:  "Impossible Travel",
}

export interface MockAnalysis {
  scan_id: string
  file_name: string
  total_logs: number
  total_threats: number
  attack_chain_count: number
  risk_score: number        // 0–10000
  threat_density: number
  generated_at: string
  status: "completed"
}

export interface MockEvent {
  event_id: string
  timestamp: string
  level: string
  source: string
  computer: string
  user_account: string
  opcode: string
  task_category: string
  process_id: string
  process_name: string
  detail: string
  cpu_usage: number
  mem_usage: number
  network_io: number
  integrity_level: string
  is_signed: boolean
  label: string
  category: string
  severity: string
  mitre_technique: string
  mitre_id: string
}

export interface MockFinding {
  id: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  detection_type: "rule" | "ml_anomaly" | "impossible_travel" | "behavioral" | "yara_match" | "heuristic"
  rule_id: string
  mitre_techniques: string[]
  mitre_ids: string[]
  affected_users: string[]
  affected_hosts: string[]
  count: number
  description: string
  timestamp: string
}

export interface MockChain {
  chain_id: string
  chain_index: number
  title: string
  computer: string
  chain_confidence: number
  kill_chain_phases: string[]
  affected_users: string[]
  affected_hosts: string[]
  events: string[]
}

export interface MockSummary {
  scan_id: string
  generated_at: string
  executive_briefing: string
  content_markdown: string
  ai_summary_report?: string
  model: string
  sections: {
    executive_summary: string
    attack_narrative: string
    affected_assets: string
    remediation_steps: string
  }
}

// ─── DATASET METADATA ────────────────────────────────────────────────────────

const DATASET_META = [
  { id: "ds-001", file: "windows_soc_data_1_ee46.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], users: ["WIN-SOC\\Admin", "WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], riskScore: 8750, threatType: "PowerShell Encoded Command Execution", mitre: "T1059.001", mitrePhase: "execution" },
  { id: "ds-002", file: "windows_soc_data_2_5bff.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-DEV-03"], users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM", "WIN-SOC\\SvcAcct"], riskScore: 7200, threatType: "LSASS Memory Access", mitre: "T1003.001", mitrePhase: "credential-access" },
  { id: "ds-003", file: "windows_soc_data_3_838b.csv", date: "2026-03-26", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-03"], users: ["WIN-SOC\\Admin", "WIN-SOC\\Dev-01", "WIN-SOC\\Backup"], riskScore: 9100, threatType: "Lateral Movement via SMB", mitre: "T1021.002", mitrePhase: "lateral-movement" },
  { id: "ds-004", file: "windows_soc_data_4_068a.csv", date: "2026-03-29", computers: ["WIN-SOC-PROD-02", "WIN-SOC-DC-01"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\Admin", "NT AUTHORITY\\NETWORK SERVICE"], riskScore: 6800, threatType: "Scheduled Task Persistence", mitre: "T1053.005", mitrePhase: "persistence" },
  { id: "ds-005", file: "windows_soc_data_5_a006.csv", date: "2026-03-27", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-04"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User2", "NT AUTHORITY\\SYSTEM"], riskScore: 8100, threatType: "Registry Run Key Modification", mitre: "T1547.001", mitrePhase: "persistence" },
  { id: "ds-006", file: "windows_soc_data_6_4379.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-05"], users: ["WIN-SOC\\User1", "WIN-SOC\\SvcDB", "NT AUTHORITY\\SYSTEM"], riskScore: 5500, threatType: "Suspicious Network Exfiltration", mitre: "T1048", mitrePhase: "exfiltration" },
  { id: "ds-007", file: "windows_soc_data_7_8735.csv", date: "2026-03-26", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-01"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\Admin", "WIN-SOC\\Guest"], riskScore: 7600, threatType: "WMI Script Execution", mitre: "T1047", mitrePhase: "execution" },
  { id: "ds-008", file: "windows_soc_data_8_11c5.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-02", "WIN-SOC-DEV-02"], users: ["WIN-SOC\\Dev-01", "NT AUTHORITY\\SYSTEM", "WIN-SOC\\Analyst"], riskScore: 8900, threatType: "Pass-the-Hash Attack", mitre: "T1550.002", mitrePhase: "defense-evasion" },
  { id: "ds-009", file: "windows_soc_data_9_c913.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-01"], users: ["WIN-SOC\\Admin", "WIN-SOC\\User3", "NT AUTHORITY\\SYSTEM"], riskScore: 9400, threatType: "DCSync Active Directory Attack", mitre: "T1003.006", mitrePhase: "credential-access" },
  { id: "ds-010", file: "windows_soc_data_10_7e32.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-DC-01"], users: ["WIN-SOC\\User1", "WIN-SOC\\SvcMail", "NT AUTHORITY\\SYSTEM"], riskScore: 6200, threatType: "Token Impersonation / Privilege Escalation", mitre: "T1134.001", mitrePhase: "privilege-escalation" },
]

const EVENT_CATS: Record<string, { title: string; severity: "critical" | "high" | "medium"; mitre: string; mitreId: string; description: string }> = {
  "T1059.001": { title: "PowerShell Encoded Command Execution", severity: "critical", mitre: "T1059.001", mitreId: "Execution", description: "Attacker executed encoded PowerShell commands (IEX Download Cradle) to bypass logging and download additional payloads from a remote C2 server." },
  "T1003.001": { title: "LSASS Memory Dump Detected", severity: "critical", mitre: "T1003.001", mitreId: "Credential Access", description: "Process accessing LSASS memory directly, consistent with credential dumping tools like Mimikatz or ProcDump." },
  "T1021.002": { title: "Lateral Movement via SMB Admin Share", severity: "high", mitre: "T1021.002", mitreId: "Lateral Movement", description: "Authenticated SMB connection to ADMIN$ or C$ share indicating lateral movement to additional hosts using stolen credentials." },
  "T1053.005": { title: "Scheduled Task Created for Persistence", severity: "high", mitre: "T1053.005", mitreId: "Persistence", description: "New scheduled task created that runs a malicious script on system startup, establishing persistence mechanism." },
  "T1547.001": { title: "Registry Run Key Modification", severity: "high", mitre: "T1547.001", mitreId: "Persistence", description: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key modified to execute malicious payload on every system boot." },
  "T1048":     { title: "Data Exfiltration Over C2 Channel", severity: "critical", mitre: "T1048", mitreId: "Exfiltration", description: "Abnormal outbound network traffic patterns detected suggesting data exfiltration to an external IP over non-standard port." },
  "T1047":     { title: "WMI Command Execution", severity: "high", mitre: "T1047", mitreId: "Execution", description: "Windows Management Instrumentation (WMI) used to spawn processes remotely, a common living-off-the-land technique." },
  "T1550.002": { title: "Pass-the-Hash Authentication Bypass", severity: "critical", mitre: "T1550.002", mitreId: "Defense Evasion", description: "NTLM hash reuse detected without proper Kerberos authentication, indicating Pass-the-Hash lateral movement technique." },
  "T1003.006": { title: "DCSync Replication Attack", severity: "critical", mitre: "T1003.006", mitreId: "Credential Access", description: "Domain Controller replication request issued by non-DC account via MS-DRSR protocol — active DCSync attack for mass credential harvesting." },
  "T1134.001": { title: "Token Impersonation / Privilege Escalation", severity: "high", mitre: "T1134.001", mitreId: "Privilege Escalation", description: "Process token impersonation detected. A low-privilege process cloned a SYSTEM token to elevate privileges without triggering UAC." },
}

const KILL_CHAIN_PHASES: Record<string, string[]> = {
  "T1059.001": ["reconnaissance", "execution", "command-and-control"],
  "T1003.001": ["credential-access", "defense-evasion"],
  "T1021.002": ["lateral-movement", "collection"],
  "T1053.005": ["persistence", "privilege-escalation"],
  "T1547.001": ["persistence", "privilege-escalation"],
  "T1048":     ["collection", "exfiltration"],
  "T1047":     ["execution", "lateral-movement"],
  "T1550.002": ["defense-evasion", "lateral-movement", "credential-access"],
  "T1003.006": ["credential-access", "collection"],
  "T1134.001": ["privilege-escalation", "defense-evasion"],
}

// ─── GENERATORS ──────────────────────────────────────────────────────────────

function genEvents(meta: typeof DATASET_META[0]): MockEvent[] {
  const cat = EVENT_CATS[meta.mitre]
  const events: MockEvent[] = []
  const baseTime = new Date(meta.date + "T23:45:54Z")

  for (let i = 0; i < 30; i++) {
    const ts = new Date(baseTime.getTime() + i * 1000).toISOString().replace("T", " ").replace("Z", "")
    const computer = meta.computers[i % meta.computers.length]
    const user = meta.users[i % meta.users.length]

    events.push({
      event_id: `evt-${meta.id}-${String(i + 1).padStart(3, "0")}`,
      timestamp: ts,
      level: "Warning",
      source: "Security",
      computer,
      user_account: user,
      opcode: "Exec",
      task_category: "Process Creation",
      process_id: String(2000 + i * 37),
      process_name: "powershell.exe",
      detail: "Encoded IEX Download",
      cpu_usage: 28 + Math.round(Math.random() * 4),
      mem_usage: 440 + Math.round(Math.random() * 20),
      network_io: 14 + Math.round(Math.random() * 3),
      integrity_level: "Medium",
      is_signed: false,
      label: "suspicious",
      category: cat.title,
      severity: cat.severity,
      mitre_technique: meta.mitre,
      mitre_id: cat.mitreId,
    })
  }
  return events
}

function genFindings(meta: typeof DATASET_META[0], events: MockEvent[]): MockFinding[] {
  const cat = EVENT_CATS[meta.mitre]
  const affectedUsers = [...new Set(events.map(e => e.user_account))]
  const affectedHosts = [...new Set(events.map(e => e.computer))]
  const findings: MockFinding[] = []

  const PROCESS_NAMES = ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "svchost.exe", "lsass.exe", "wmiprvse.exe"]
  const SOURCE_IPS = ["192.168.1.47", "10.0.0.23", "172.16.4.88", "192.168.2.101", "10.1.0.55", "172.31.0.9"]
  const DEST_IPS = ["45.77.12.34", "104.21.88.3", "185.220.101.5", "31.13.72.49", "198.41.0.4"]
  const PORTS = [4444, 8080, 1337, 443, 8443, 6666, 31337]
  const PARENT_PROCS = ["explorer.exe", "services.exe", "winlogon.exe", "taskhost.exe", "svchost.exe"]

  // ── 30 CRITICAL findings (one per suspicious log event) ──────────────────
  for (let i = 0; i < 30; i++) {
    const evt = events[i]
    const proc = PROCESS_NAMES[i % PROCESS_NAMES.length]
    const srcIp = SOURCE_IPS[i % SOURCE_IPS.length]
    const dstIp = DEST_IPS[i % DEST_IPS.length]
    const port = PORTS[i % PORTS.length]
    findings.push({
      id: `fnd-${meta.id}-crit-${String(i + 1).padStart(3, "0")}`,
      severity: "critical",
      title: `${cat.title} — Event #${i + 1}`,
      detection_type: "rule",
      rule_id: `SOC-${meta.mitre.replace(".", "-")}-${String(i + 1).padStart(3, "0")}`,
      mitre_techniques: [cat.title],
      mitre_ids: [meta.mitre],
      affected_users: [meta.users[i % meta.users.length]],
      affected_hosts: [meta.computers[i % meta.computers.length]],
      count: 1,
      description: `${cat.description} Process: ${proc} (PID: ${2000 + i * 37}) spawned by ${PARENT_PROCS[i % PARENT_PROCS.length]}. Outbound connection to ${dstIp}:${port} from ${srcIp}. CPU: ${28 + (i % 5)}%, Mem: ${440 + (i % 20)}MB, Net I/O: ${14 + (i % 4)}MB/s. Event ID: 4688.`,
      timestamp: evt.timestamp,
    })
  }

  // ── 15 HIGH findings (ML Anomaly detections) ─────────────────────────────
  const HIGH_TITLES = [
    "Anomalous Process Behavior (ML Anomaly)",
    "Suspicious Child Process Spawned",
    "Unusual Network Connection Pattern",
    "Memory Scraping Attempt Detected",
    "Abnormal Authentication Sequence",
    "Suspicious File Write in System32",
    "Elevated CPU by Unsigned Binary",
    "PowerShell Download Cradle Detected",
    "Unusual LDAP Query Volume",
    "Remote Thread Injection Attempt",
    "Suspicious WMI Subscription Created",
    "Outbound DNS Tunneling Pattern",
    "API Hooking Detected in Process",
    "Unsigned DLL Loaded by System Process",
    "Excessive Failed Logon Attempts",
  ]
  const HIGH_DESCS = [
    "Isolation Forest model flagged this process cluster as a 6.2-sigma outlier. CPU deviation >3x baseline, memory working set doubled within 2 minutes.",
    "Suspicious child process spawned from parent not typically associated with this user. Likely a second-stage payload dropper executing from temp directory.",
    "Connection to IP outside the organization's geofence. Destination classified as Bulletproof Hosting provider. ASN: AS24940.",
    "Process accessed LSASS virtual memory pages without debug privilege. Tool fingerprint matches ProcDump v10.x behavior.",
    "Authentication token requested for 8 different service accounts within 90 seconds. Consistent with credential stuffing or automated spray pattern.",
    "File written to C:\\Windows\\System32 by a non-system process. SHA256 not found in known-good catalog. File: update_kb.dll",
    "Binary not in application whitelist executing with 32% average CPU. Signed status: false. Spawned from cmd.exe with obfuscated arguments.",
    "PowerShell used -enc flag with Base64-encoded payload. Decoded payload attempts IEX download from pastebin-style domain.",
    "1,200 LDAP enumeration queries in under 60 seconds. Matches AD recon tool (BloodHound/SharpHound) behavioral signature.",
    "CreateRemoteThread API called from non-system process into lsass.exe address space. Process injection confirmed.",
    "WMI permanent subscription created that triggers on system start. Command: powershell -WindowStyle hidden -File C:\\ProgramData\\svc.ps1",
    "DNS queries for non-existent long subdomains — consistent with DNS-over-HTTPS tunneling or C2 beaconing pattern.",
    "API hooking detected by inline patch analysis. Target: NtReadVirtualMemory in ntdll.dll. Likely evasion of EDR telemetry.",
    "Unsigned DLL injected via AppInit_DLLs registry key. DLL loaded into every GUI process on the system.",
    "342 failed logon attempts against 4 different accounts within 5 minutes from the same source IP. Brute-force attack pattern.",
  ]
  for (let i = 0; i < 15; i++) {
    const evt = events[i % events.length]
    findings.push({
      id: `fnd-${meta.id}-high-${String(i + 1).padStart(3, "0")}`,
      severity: "high",
      title: HIGH_TITLES[i],
      detection_type: i % 3 === 0 ? "rule" : "ml_anomaly",
      rule_id: `ML-HIGH-${meta.id}-${String(i + 1).padStart(3, "0")}`,
      mitre_techniques: ["Scripting Interpreter", "Defense Evasion"],
      mitre_ids: ["T1059", "T1562"],
      affected_users: [meta.users[i % meta.users.length]],
      affected_hosts: [meta.computers[i % meta.computers.length]],
      count: 1,
      description: HIGH_DESCS[i],
      timestamp: new Date(new Date(evt.timestamp).getTime() + i * 3000).toISOString().replace("T", " ").replace("Z", ""),
    })
  }

  // ── 10 MEDIUM findings ────────────────────────────────────────────────────
  const MED_TITLES = [
    "High-Frequency Event Burst Detected",
    "Scheduled Task Modification",
    "Registry Persistence Key Written",
    "Unusual Service Account Logon",
    "SMB Share Enumeration",
    "PowerShell Script Block Logging Disabled",
    "Firewall Rule Added by Non-Admin Process",
    "Suspicious Temp Directory Execution",
    "Large Data Staging in Temp Folder",
    "Unusual Process Lineage",
  ]
  const MED_DESCS = [
    "30 identical warning-level events in a 30-second window detected. Statistical anomaly consistent with coordinated automation or attack sweep.",
    "Scheduled task modified to run at irregular intervals. Task path: \\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified by process not in admin group. Value: svchost32.exe -k netsvcs.",
    "Service account WIN-SOC\\SvcAcct logged in interactively outside IT maintenance window (2AM local). Geo: internal network.",
    "SMB share enumeration detected — net view and net use commands run in sequence. Potential precursor to lateral movement.",
    "PowerShell Script Block Logging disabled via registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging → 0.",
    "New inbound firewall rule added: Allow TCP 4445 from Any. Rule added by process: InstallUtil.exe. Possible persistence.",
    "Binary executing from C:\\Users\\Public\\Temp or %APPDATA%\\Roaming with no recognized digital signature.",
    "7.3GB of data copied to C:\\Temp\\archive.zip in 4 minutes. Potential data staging before exfiltration event.",
    "Unusual parent-child relationship: winword.exe → cmd.exe → powershell.exe. Classic Office macro shellcode dropper chain.",
  ]
  for (let i = 0; i < 10; i++) {
    const evt = events[i % events.length]
    findings.push({
      id: `fnd-${meta.id}-med-${String(i + 1).padStart(3, "0")}`,
      severity: "medium",
      title: MED_TITLES[i],
      detection_type: i % 2 === 0 ? "ml_anomaly" : "rule",
      rule_id: `MED-RULE-${meta.id}-${String(i + 1).padStart(3, "0")}`,
      mitre_techniques: ["Persistence", "Discovery"],
      mitre_ids: ["T1053", "T1082"],
      affected_users: [meta.users[i % meta.users.length]],
      affected_hosts: [meta.computers[i % meta.computers.length]],
      count: 1,
      description: MED_DESCS[i],
      timestamp: new Date(new Date(evt.timestamp).getTime() + i * 5000).toISOString().replace("T", " ").replace("Z", ""),
    })
  }

  return findings
}


function genChains(meta: typeof DATASET_META[0], events: MockEvent[]): MockChain[] {
  const phases = KILL_CHAIN_PHASES[meta.mitre] || ["execution"]
  const hosts = meta.computers

  return hosts.map((host, i) => ({
    chain_id: `chain-${meta.id}-${String(i + 1).padStart(2, "0")}`,
    chain_index: i + 1,
    title: `${meta.threatType} on ${host}`,
    computer: host,
    chain_confidence: 0.85 + i * 0.05,
    kill_chain_phases: phases,
    affected_users: meta.users.filter((_, j) => j !== i),
    affected_hosts: [host],
    events: events.filter(e => e.computer === host).map(e => e.event_id),
  }))
}

function genSummary(meta: typeof DATASET_META[0], analysis: MockAnalysis, findings: MockFinding[], chains: MockChain[]): MockSummary {
  const cat = EVENT_CATS[meta.mitre]
  const riskPct = Math.round(analysis.risk_score / 100)
  const affectedUsers = [...new Set(findings.flatMap(f => f.affected_users))]
  const affectedHosts = [...new Set(findings.flatMap(f => f.affected_hosts))]
  const threatLevel = riskPct >= 80 ? "CRITICAL" : riskPct >= 50 ? "HIGH" : "MEDIUM"

  const execSummary = `A ${threatLevel}-severity threat campaign was detected in dataset ${meta.file}. Analysis identified ${analysis.total_threats} suspicious events across ${affectedHosts.length} hosts, with a risk score of ${riskPct}%. The primary attack vector is **${meta.threatType}** (MITRE ATT&CK: ${meta.mitre}), affecting users ${affectedUsers.join(", ")}. Immediate incident response is recommended.`

  const narrative = `**Attack Timeline:**\n\nBetween ${meta.date} 23:45:54 and 23:46:23 UTC, 30 coordinated attack events were executed across ${affectedHosts.join(" and ")}. All events originated from \`powershell.exe\` with "Encoded IEX Download" technique, consistent with a staged payload delivery attack (MITRE ${meta.mitre}).\n\n**Attack Phases Identified:** ${KILL_CHAIN_PHASES[meta.mitre]?.map(p => `\`${p}\``).join(" → ")}\n\nThe threat actor likely used an encoded PowerShell invocation expression (IEX) to download secondary malware from a remote C2 endpoint, bypassing traditional AV signature detection.`

  const riskLevel = riskPct >= 80 ? "🔴 CRITICAL" : (riskPct >= 50 ? "🟠 HIGH" : "🟡 MEDIUM")

  const reportPattern = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | ${meta.file} |
| Generated On | ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC |
| Risk Level | ${riskLevel} (${riskPct}%) |
| Total Logs | ${analysis.total_logs.toLocaleString()} |
| Threat Events | ${analysis.total_threats} |
| Attack Chains | ${chains.length} |
| Affected Hosts | ${affectedHosts.length} |
| Affected Users | ${affectedUsers.length} |

---

## 🧠 2. EXECUTIVE SUMMARY
A ${riskPct >= 80 ? 'critical' : 'significant'} threat campaign was detected in dataset **${meta.file}**.
Primary attack vector: **${cat.title} (${meta.mitre})**
Attack observed across:
${affectedHosts.map(h => `- **${h}**`).join('\n')}

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 23:45:54 | ${affectedHosts[0]} | Activity sequence initiated |
| 23:46:05 | ${affectedHosts[0]} | ${cat.title} triggered |
| 23:46:23 | ${affectedHosts[0]} | Suspicious pattern completion |

---

## 🧩 4. ATTACK CHAIN
Initial Access (Suspicious Payload)
      ↓
Execution (${cat.title})
      ↓
Payload Delivery (MITRE ${meta.mitre})
      ↓
Command & Control Communication

---

## ⚙️ 5. TECHNICAL DETAILS
| Category | Details |
|----------|---------|
| Process | powershell.exe / services.exe |
| Technique | ${cat.title} |
| MITRE ID | ${meta.mitre} |
| CPU Usage | 28–32% |
| Memory Usage | 440–460 MB |
| Network I/O | 14–17 MB/s |

---

## 🎯 6. MITRE ATT&CK MAPPING
| Technique ID | Name | Description |
|--------------|------|-------------|
| ${meta.mitre} | ${cat.title} | ${cat.description} |
| T1105 | Ingress Tool Transfer | Payload downloaded from remote server |
| T1071 | Application Layer Protocol | C2 communication |

---

## 🚨 7. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| ${riskLevel} | ${cat.title} | ${analysis.total_threats} |
| 🟠 HIGH | Anomalous Process Behavior (ML) | 15 |
| 🟡 MEDIUM | High-Frequency Event Burst | 10 |

---

## 🖥️ 8. AFFECTED ENTITIES
**Hosts**
${affectedHosts.join('\n')}

**Users**
${affectedUsers.join('\n')}

---

## 🛡️ 9. RECOMMENDATIONS
- Block **${cat.title}** execution patterns
- Enable Advanced Script Block Logging (GPO)
- Isolate affected hosts: ${affectedHosts.join(', ')}
- Monitor outbound traffic for C2 beacon patterns
- Deploy EDR detection rules for MITRE ${meta.mitre}

---

## 📊 10. RISK ASSESSMENT
Overall Risk Score: **${riskPct}% (${riskPct >= 80 ? 'CRITICAL' : 'HIGH'})**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | ${riskPct >= 80 ? 'CRITICAL' : 'HIGH'} |
| Confidence | 98% |
`;

  return {
    scan_id: meta.id,
    generated_at: new Date(meta.date + "T23:50:00Z").toISOString(),
    executive_briefing: execSummary,
    content_markdown: reportPattern,
    ai_summary_report: reportPattern,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: execSummary,
      attack_narrative: narrative,
      affected_assets: `**Hosts:** ${affectedHosts.join(", ")}\n\n**Users:** ${affectedUsers.join(", ")}`,
      remediation_steps: `1. **Isolate** affected hosts (${affectedHosts.join(", ")}) from the network immediately.\n2. **Revoke** credentials for affected accounts: ${affectedUsers.join(", ")}.\n3. **Review** and kill suspicious PowerShell processes (PID: ${findings[0].count}+ instances).\n4. **Enable** PowerShell Script Block Logging (Event ID 4104) to capture decoded commands.`,
    },
  }
}

// ─── BUILD ALL MOCK DATA ──────────────────────────────────────────────────────

function buildMockDataset(meta: typeof DATASET_META[0]) {
  const events = genEvents(meta)
  const findings = genFindings(meta, events)
  const analysis: MockAnalysis = {
    scan_id: meta.id,
    file_name: meta.file,
    total_logs: 10000,
    total_threats: 30,
    attack_chain_count: meta.computers.length,
    risk_score: meta.riskScore,
    threat_density: 0.3,
    generated_at: new Date(meta.date + "T23:50:00Z").toISOString(),
    status: "completed",
  }
  const chains = genChains(meta, events)
  const summary = genSummary(meta, analysis, findings, chains)

  return { analysis, events, findings, chains, summary }
}

// ─── USER UPLOAD MOCK DATA ────────────────────────────────────────────────────

const UPLOAD_META = {
  id: "mock-upload-id",
  file: "uploaded_log_analysis.csv",
  date: new Date().toISOString().split("T")[0],
  computers: ["WS-PROD-99", "WS-PROD-102"],
  users: ["CORP\\jsmith", "SYSTEM"],
  riskScore: 9200,
  threatType: "Advanced Persistent Threat (APT) Detection",
  mitre: "T1059.001",
  mitrePhase: "execution"
}

function genMockUploadFindings(): MockFinding[] {
  const ts = new Date().toISOString()
  const findings: MockFinding[] = []
  
  // 12 critical
  for(let i=0; i<12; i++) {
    findings.push({
      id: `fnd-upload-crit-${i}`,
      severity: "critical",
      title: `Critical Vulnerability Exploit #${i+1}`,
      detection_type: "rule",
      rule_id: "CRIT-001",
      mitre_techniques: ["Exploitation for Privilege Escalation"],
      mitre_ids: ["T1068"],
      affected_users: ["SYSTEM"],
      affected_hosts: ["WS-PROD-99"],
      count: 1,
      description: "Critical memory corruption exploit detected targeting kernel-level services.",
      timestamp: ts
    })
  }

  // 45 high
  for(let i=0; i<45; i++) {
    findings.push({
      id: `fnd-upload-high-${i}`,
      severity: "high",
      title: `High Risk Activity #${i+1}`,
      detection_type: "ml_anomaly",
      rule_id: "HIGH-002",
      mitre_techniques: ["Remote Access Software"],
      mitre_ids: ["T1219"],
      affected_users: ["CORP\\jsmith"],
      affected_hosts: ["WS-PROD-99", "WS-PROD-102"],
      count: i + 2,
      description: "Suspicious RDP pattern detected outside of business hours with abnormal data transfer volumes.",
      timestamp: ts
    })
  }

  // 50 medium
  for(let i=0; i<50; i++) {
    findings.push({
      id: `fnd-upload-med-${i}`,
      severity: "medium",
      title: `Medium Severity Warning #${i+1}`,
      detection_type: "rule",
      rule_id: "MED-003",
      mitre_techniques: ["Unsecured Credentials"],
      mitre_ids: ["T1552"],
      affected_users: ["CORP\\jsmith"],
      affected_hosts: ["WS-PROD-102"],
      count: 1,
      description: "Configuration file read by unauthorized process potential for credential harvesting.",
      timestamp: ts
    })
  }

  // 20 info
  for(let i=0; i<20; i++) {
    findings.push({
      id: `fnd-upload-info-${i}`,
      severity: "info",
      title: `Information Event #${i+1}`,
      detection_type: "rule",
      rule_id: "INFO-004",
      mitre_techniques: ["System Information Discovery"],
      mitre_ids: ["T1082"],
      affected_users: ["CORP\\jsmith"],
      affected_hosts: ["WS-PROD-99"],
      count: 1,
      description: "Standard system discovery commands being executed as part of routine maintenance or environmental awareness.",
      timestamp: ts
    })
  }

  return findings
}

function buildUserUploadDataset() {
  const findings = genMockUploadFindings()
  const analysis: MockAnalysis = {
    scan_id: UPLOAD_META.id,
    file_name: UPLOAD_META.file,
    total_logs: 45200,
    total_threats: 127,
    attack_chain_count: 1,
    risk_score: 9200,
    threat_density: 0.8,
    generated_at: new Date().toISOString(),
    status: "completed",
  }
  
  const chains: MockChain[] = [{
    chain_id: "chain-upload-01",
    chain_index: 1,
    title: "APT Lateral Movement Chain",
    computer: "WS-PROD-99",
    chain_confidence: 0.94,
    kill_chain_phases: ["initial-access", "execution", "persistence", "lateral-movement"],
    affected_users: ["CORP\\jsmith", "SYSTEM"],
    affected_hosts: ["WS-PROD-99", "WS-PROD-102"],
    events: ["evt-up-001", "evt-up-002", "evt-up-003"]
  }]

  const summary = genSummary(UPLOAD_META, analysis, findings, chains)

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER001 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/user001logs.json — rich multi-chain APT campaign data

function buildUser001Dataset() {
  // ---------- Analysis ----------
  const analysis: MockAnalysis = {
    scan_id: "user-001",
    file_name: "user001logs.csv",
    total_logs: 10000,
    total_threats: 120,
    attack_chain_count: 6,
    risk_score: 9700,
    threat_density: 1.2,
    generated_at: "2026-04-06T11:43:31Z",
    status: "completed",
  }

  // ---------- Findings (from attacked_logs) ----------
  const labelToSeverity = (label: string, level: string): "critical" | "high" | "medium" | "low" | "info" => {
    if (label === "malicious" || level === "Critical") return "critical"
    if (label === "suspicious" || level === "Warning") return "high"
    return "medium"
  }

  const findings: MockFinding[] = [
    // Chain 1 — PowerShell C2 & Persistence
    { id: "fnd-u001-01", severity: "critical", title: "PowerShell Encoded Command Execution (IEX Download)", detection_type: "rule", rule_id: "SOC-T1059-001-001", mitre_techniques: ["PowerShell Encoded Command Execution"], mitre_ids: ["T1059.001"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 30, description: "Attacker executed encoded PowerShell (IEX) commands to download and run a C2 beacon payload from a remote server (185.220.101.45:443), bypassing AV signature detection.", timestamp: "2026-04-02 23:45:54" },
    { id: "fnd-u001-02", severity: "high", title: "Scheduled Task Created for C2 Beacon Persistence", detection_type: "behavioral", rule_id: "SOC-T1053-005-001", mitre_techniques: ["Scheduled Task/Job"], mitre_ids: ["T1053.005"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01"], count: 8, description: "Attacker created and modified scheduled tasks to maintain C2 persistence across reboots. Task execution interval was altered to reduce detection window.", timestamp: "2026-04-02 23:46:10" },
    { id: "fnd-u001-03", severity: "high", title: "Malicious Service Installed for C2 Persistence", detection_type: "yara_match", rule_id: "SOC-T1543-003-001", mitre_techniques: ["Create or Modify System Process: Windows Service"], mitre_ids: ["T1543.003"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01"], count: 1, description: "An unsigned malicious service was installed (7045) to ensure the C2 beacon persists as a Windows service, running as SYSTEM with no digital signature.", timestamp: "2026-04-02 23:46:40" },
    // Chain 2 — LSASS & Credential Dump
    { id: "fnd-u001-04", severity: "critical", title: "LSASS Memory Dump — Credential Harvesting (Mimikatz)", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-001", mitre_techniques: ["OS Credential Dumping: LSASS Memory"], mitre_ids: ["T1003.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], count: 15, description: "ML model flagged mimikatz.exe accessing LSASS memory — a 9.1-sigma deviation from baseline. NTLM hash extraction confirmed via memory dump signature.", timestamp: "2026-04-02 23:50:00" },
    { id: "fnd-u001-05", severity: "critical", title: "Pass-the-Hash Authentication Bypass", detection_type: "ml_anomaly", rule_id: "SOC-T1550-002-001", mitre_techniques: ["Use Alternate Authentication Material: Pass the Hash"], mitre_ids: ["T1550.002"], affected_users: ["WIN-SOC\\ServiceAcct"], affected_hosts: ["WIN-SOC-PROD-02"], count: 3, description: "Isolation Forest model detected NTLM hash reuse without Kerberos negotiation — 8.4-sigma outlier. Pass-the-Hash lateral movement confirmed.", timestamp: "2026-04-02 23:50:30" },
    { id: "fnd-u001-06", severity: "critical", title: "SeDebugPrivilege Granted — Privilege Escalation", detection_type: "behavioral", rule_id: "SOC-T1548-001", mitre_techniques: ["Abuse Elevation Control Mechanism"], mitre_ids: ["T1548"], affected_users: ["WIN-SOC\\ServiceAcct"], affected_hosts: ["WIN-SOC-PROD-02"], count: 2, description: "Behavioral engine flagged SeDebugPrivilege assignment outside of expected maintenance windows. Privilege elevation by non-admin process chain detected.", timestamp: "2026-04-02 23:51:30" },
    // Chain 3 — Lateral Movement
    { id: "fnd-u001-07", severity: "critical", title: "PsExec Lateral Movement to WIN-SOC-PROD-03", detection_type: "rule", rule_id: "SOC-T1021-002-001", mitre_techniques: ["Remote Services: SMB/Windows Admin Shares"], mitre_ids: ["T1021.002"], affected_users: ["WIN-SOC\\ServiceAcct"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"], count: 20, description: "PsExec was used to move laterally from WIN-SOC-PROD-02 to WIN-SOC-PROD-03 via ADMIN$ SMB share, spawning a SYSTEM-level remote command shell.", timestamp: "2026-04-03 00:00:00" },
    { id: "fnd-u001-08", severity: "high", title: "Internal Network & Process Discovery on Remote Host", detection_type: "heuristic", rule_id: "SOC-T1016-001", mitre_techniques: ["System Network Configuration Discovery", "Process Discovery"], mitre_ids: ["T1016", "T1057", "T1083"], affected_users: ["WIN-SOC\\ServiceAcct"], affected_hosts: ["WIN-SOC-PROD-03"], count: 4, description: "Heuristic engine detected rapid sequential enumeration commands (net localgroup, ipconfig, tasklist, dir) executed within 90 seconds — characteristic post-exploitation recon pattern.", timestamp: "2026-04-03 00:01:30" },
    // Chain 4 — Ransomware
    { id: "fnd-u001-09", severity: "critical", title: "Ransomware Staging — Shadow Copy Deletion & Encryption", detection_type: "behavioral", rule_id: "SOC-T1490-001", mitre_techniques: ["Inhibit System Recovery", "Data Encrypted for Impact"], mitre_ids: ["T1490", "T1486"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], count: 10, description: "Behavioral analysis flagged vssadmin + bcdedit + mass file encryption sequence — classic ransomware kill chain. ransomware_stage.exe CPU spiked to 92%.", timestamp: "2026-04-03 00:10:00" },
    { id: "fnd-u001-10", severity: "critical", title: "Windows Defender & Logging Disabled (Defense Evasion)", detection_type: "rule", rule_id: "SOC-T1562-001-001", mitre_techniques: ["Impair Defenses: Disable or Modify Tools"], mitre_ids: ["T1562.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], count: 7, description: "sc.exe stopped Windows Defender service and reg.exe disabled audit logging to blind the SOC before and during ransomware deployment.", timestamp: "2026-04-03 00:12:00" },
    // Chain 5 — DCSync / Golden Ticket
    { id: "fnd-u001-11", severity: "critical", title: "DCSync Attack — krbtgt Hash Extracted (Golden Ticket Risk)", detection_type: "ml_anomaly", rule_id: "SOC-T1003-006-001", mitre_techniques: ["OS Credential Dumping: DCSync"], mitre_ids: ["T1003.006"], affected_users: ["WIN-SOC\\Domain Admin"], affected_hosts: ["WIN-SOC-DC-01"], count: 8, description: "ML model detected MS-DRSR replication requests originating from a non-DC endpoint — 10-sigma anomaly. krbtgt hash extracted enabling Golden Ticket forgery.", timestamp: "2026-04-03 00:20:00" },
    { id: "fnd-u001-12", severity: "critical", title: "Kerberoasting & Golden Ticket Forgery", detection_type: "heuristic", rule_id: "SOC-T1558-001", mitre_techniques: ["Steal or Forge Kerberos Tickets: Golden Ticket", "Kerberoasting"], mitre_ids: ["T1558.001", "T1558.003", "T1558"], affected_users: ["WIN-SOC\\Domain Admin", "WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-DC-01"], count: 5, description: "Heuristic engine flagged 1,200+ LDAP SPN queries in 60 seconds (Kerberoasting pattern). TGT requested with forged PAC data (Golden Ticket). Overpass-the-Hash also confirmed.", timestamp: "2026-04-03 00:21:00" },
    // Chain 6 — Phishing / DNS Exfil
    { id: "fnd-u001-13", severity: "high", title: "Phishing Document Opened — Macro Execution", detection_type: "yara_match", rule_id: "SOC-T1566-001", mitre_techniques: ["Phishing: Spearphishing Attachment", "User Execution: Malicious File"], mitre_ids: ["T1566.001", "T1204.002"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-01"], count: 10, description: "YARA rule MACRO_DROPPER_v3 matched invoice_april.docm — embedded VBA shellcode dropper detected. Macro spawned WScript and MSHTA for second-stage payload delivery.", timestamp: "2026-04-03 00:30:00" },
    { id: "fnd-u001-14", severity: "critical", title: "DNS Tunneling Exfiltration via dnscat", detection_type: "ml_anomaly", rule_id: "SOC-T1048-001-001", mitre_techniques: ["Exfiltration Over DNS", "Exfiltration Over Alternative Protocol"], mitre_ids: ["T1048.001", "T1048", "T1071.004"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-01"], count: 12, description: "ML model detected anomalous DNS TXT query volume (350+ subdomain queries/min to exfil.attacker.io). Shannon entropy analysis confirmed encoded data in subdomains — DNS tunneling exfiltration.", timestamp: "2026-04-03 00:32:00" },
  ]

  // ---------- Attack Chains ----------
  const chains: MockChain[] = [
    {
      chain_id: "chain-ds-001-01",
      chain_index: 1,
      title: "PowerShell C2 Beacon & Persistence",
      computer: "WIN-SOC-PROD-01",
      chain_confidence: 0.97,
      kill_chain_phases: ["execution", "persistence", "command-and-control"],
      affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"],
      events: ["fnd-ds-001-log-1", "fnd-ds-001-log-2", "fnd-ds-001-log-3", "fnd-ds-001-log-8", "fnd-ds-001-log-9"],
    },
    {
      chain_id: "chain-ds-001-02",
      chain_index: 2,
      title: "LSASS Credential Dump & Pass-the-Hash",
      computer: "WIN-SOC-PROD-02",
      chain_confidence: 0.98,
      kill_chain_phases: ["credential-access", "privilege-escalation"],
      affected_users: ["WIN-SOC\\ServiceAcct", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-02"],
      events: ["fnd-ds-001-log-11", "fnd-ds-001-log-12", "fnd-ds-001-log-13"],
    },
    {
      chain_id: "chain-ds-001-03",
      chain_index: 3,
      title: "PsExec Lateral Movement & Internal Discovery",
      computer: "WIN-SOC-PROD-03",
      chain_confidence: 0.95,
      kill_chain_phases: ["lateral-movement", "discovery"],
      affected_users: ["WIN-SOC\\ServiceAcct"],
      affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"],
      events: ["fnd-ds-001-log-16", "fnd-ds-001-log-17", "fnd-ds-001-log-18"],
    },
    {
      chain_id: "chain-ds-001-04",
      chain_index: 4,
      title: "Ransomware Staging & Defense Evasion",
      computer: "WIN-SOC-PROD-04",
      chain_confidence: 0.99,
      kill_chain_phases: ["defense-evasion", "persistence", "impact"],
      affected_users: ["NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-04"],
      events: ["fnd-ds-001-log-23", "fnd-ds-001-log-25", "fnd-ds-001-log-27"],
    },
    {
      chain_id: "chain-ds-001-05",
      chain_index: 5,
      title: "DCSync & Golden Ticket / Kerberoasting",
      computer: "WIN-SOC-DC-01",
      chain_confidence: 0.99,
      kill_chain_phases: ["credential-access"],
      affected_users: ["WIN-SOC\\Domain Admin", "WIN-SOC\\User2"],
      affected_hosts: ["WIN-SOC-DC-01"],
      events: ["fnd-ds-001-log-29", "fnd-ds-001-log-30", "fnd-ds-001-log-31"],
    },
    {
      chain_id: "chain-ds-001-06",
      chain_index: 6,
      title: "Phishing → Macro Execution → DNS Exfiltration",
      computer: "WIN-SOC-PROD-01",
      chain_confidence: 0.96,
      kill_chain_phases: ["initial-access", "execution", "defense-evasion", "command-and-control", "exfiltration"],
      affected_users: ["WIN-SOC\\User2"],
      affected_hosts: ["WIN-SOC-PROD-01"],
      events: ["fnd-ds-001-log-34", "fnd-ds-001-log-38", "fnd-ds-001-log-39"],
    },
  ]

  // ---------- Summary (uses the rich ai_summary_report from the JSON) ----------
  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user001logs.csv |
| Generated On | 2026-04-06 11:43:31 UTC |
| Risk Level | 🔴 CRITICAL (97%) |
| Total Logs | 10,000 |
| Threat Events | 120 |
| Attack Chains | 6 |
| Affected Hosts | 5 |
| Affected Users | 6 |

---

## 🧠 2. EXECUTIVE SUMMARY
A multi-stage critical threat campaign was detected spanning **6 distinct attack chains**.
Primary attack vectors: PowerShell Encoded Command Execution, LSASS Credential Dumping, Lateral Movement via PsExec, Ransomware Staging, Phishing-driven Initial Access, and Data Exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01**
- **WIN-SOC-PROD-02**
- **WIN-SOC-PROD-03**
- **WIN-SOC-PROD-04**
- **WIN-SOC-DC-01**

Immediate containment and forensic response is required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-02 23:45:54 | WIN-SOC-PROD-01 | Encoded IEX Download (PowerShell C2) |
| 2026-04-02 23:50:10 | WIN-SOC-PROD-01 | Scheduled Task Created for C2 Persistence |
| 2026-04-02 23:50:00 | WIN-SOC-PROD-02 | LSASS Memory Access (Mimikatz) |
| 2026-04-03 00:00:00 | WIN-SOC-PROD-03 | PsExec Lateral Movement Initiated |
| 2026-04-03 00:10:00 | WIN-SOC-PROD-04 | Vssadmin Shadow Copy Delete (Ransomware Prep) |
| 2026-04-03 00:20:00 | WIN-SOC-DC-01 | DCSync Attack — krbtgt Hash Extracted |
| 2026-04-03 00:30:00 | WIN-SOC-PROD-01 | Phishing Document Opened — Macro Execution |
| 2026-04-03 00:32:00 | WIN-SOC-PROD-01 | DNS Tunneling Exfiltration Detected |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** PowerShell Execution → Persistence (Sched Task + Service) → C2 Beacon
- **Chain 2:** Credential Access (LSASS / Mimikatz) → Pass-the-Hash → Privilege Escalation
- **Chain 3:** Lateral Movement via PsExec → Remote Shell → Internal Discovery
- **Chain 4:** Defense Evasion (Defender Off) → Ransomware Staging → Impact (Encryption)
- **Chain 5:** DCSync (krbtgt) → Golden Ticket Forgery → Kerberoasting
- **Chain 6:** Phishing → VBA Macro → MSHTA → DNS Tunneling Exfiltration

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1053.005 | Scheduled Task/Job | Persistence |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access |
| T1558.003 | Kerberoasting | Credential Access |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1048.001 | Exfiltration Over Alternative Protocol: DNS | Exfiltration |
| T1071.004 | Application Layer Protocol: DNS | Command & Control |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | PowerShell Encoded Command Execution | 30 |
| 🔴 CRITICAL | LSASS Credential Dump (Mimikatz) | 15 |
| 🔴 CRITICAL | DCSync Attack — krbtgt Extracted | 8 |
| 🔴 CRITICAL | Ransomware Staging / Shadow Copy Deletion | 10 |
| 🔴 CRITICAL | Pass-the-Hash Authentication Bypass | 3 |
| 🟠 HIGH | PsExec Lateral Movement | 20 |
| 🟠 HIGH | DNS Tunneling Exfiltration | 12 |
| 🟠 HIGH | Phishing Document Macro Execution | 10 |
| 🟡 MEDIUM | Scheduled Task Persistence | 8 |
| 🟡 MEDIUM | Windows Defender & Logging Disabled | 7 |
| 🟡 MEDIUM | Kerberoasting / Golden Ticket | 5 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — Initial access, C2 beacon, phishing, exfiltration
- WIN-SOC-PROD-02 — LSASS dump, Pass-the-Hash, PsExec pivot
- WIN-SOC-PROD-03 — Lateral movement target, internal recon
- WIN-SOC-PROD-04 — Ransomware deployment target
- WIN-SOC-DC-01 — DCSync, Golden Ticket, Kerberoasting

**Users**
- WIN-SOC\\Admin
- WIN-SOC\\User1
- WIN-SOC\\User2
- WIN-SOC\\ServiceAcct
- NT AUTHORITY\\SYSTEM
- WIN-SOC\\Domain Admin

---

## 🛡️ 8. RECOMMENDATIONS
- Block PowerShell Encoded Command Execution patterns and enable **Script Block Logging** (Event ID 4104)
- **Isolate all affected hosts** immediately (WIN-SOC-PROD-01 through -04, WIN-SOC-DC-01)
- Monitor and block outbound **DNS tunneling** traffic patterns (long TXT subdomains)
- Deploy EDR rules targeting **LSASS access** (sysmon event 10) and **mimikatz signatures**
- Audit and **reset credentials** for all 6 affected accounts including krbtgt
- Enable **Protected Users** security group for all privileged accounts
- Enforce **MFA** and **PAW (Privileged Access Workstations)** for admin accounts
- Review and harden **DCSync replication permissions** in Active Directory

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 97% (CRITICAL)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | CRITICAL |
| Confidence | 98% |
`

  const summary: MockSummary = {
    scan_id: "user-001",
    generated_at: "2026-04-06T11:43:31Z",
    executive_briefing: "A CRITICAL multi-stage APT campaign was detected in user001logs.csv. Analysis identified 120 threat events across 5 hosts and 6 attack chains. Primary vectors: PowerShell Encoded Command Execution, LSASS Credential Dumping, PsExec Lateral Movement, Ransomware Staging, DCSync Attack, and DNS Tunneling Exfiltration. Immediate containment and forensic response is required.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A CRITICAL multi-stage APT campaign was detected in user001logs.csv spanning 6 attack chains. Primary attack vectors include PowerShell Encoded Command Execution (T1059.001), LSASS Credential Dumping (T1003.001), PsExec Lateral Movement (T1021.002), Ransomware Staging (T1490/T1486), DCSync Attack (T1003.006), and DNS Tunneling Exfiltration (T1048.001). 5 hosts and 6 user accounts were compromised. Risk Score: 97% CRITICAL.",
      attack_narrative: "Between 2026-04-02 23:45 UTC and 2026-04-03 00:33 UTC, a sophisticated threat actor executed a 6-chain attack campaign. Initial access was gained via Phishing (invoice_april.docm). PowerShell C2 was established with scheduled task persistence. Mimikatz dumped LSASS credentials enabling Pass-the-Hash and lateral movement via PsExec. On WIN-SOC-PROD-04, ransomware was deployed after disabling Defender. On the domain controller, DCSync extracted the krbtgt hash enabling Golden Ticket persistence. DNS tunneling via dnscat exfiltrated sensitive data.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01, WIN-SOC-PROD-02, WIN-SOC-PROD-03, WIN-SOC-PROD-04, WIN-SOC-DC-01\n\n**Users:** WIN-SOC\\Admin, WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\ServiceAcct, NT AUTHORITY\\SYSTEM, WIN-SOC\\Domain Admin",
      remediation_steps: "1. **Isolate** all 5 affected hosts from the network immediately.\n2. **Reset** krbtgt account password twice (Golden Ticket invalidation) and all 6 compromised user accounts.\n3. **Enable** PowerShell Script Block Logging (Event ID 4104) and LSASS protection (Credential Guard).\n4. **Block** outbound DNS tunneling — filter long subdomains and DNS-over-HTTPS to untrusted resolvers.\n5. **Deploy** EDR memory protection rules for Mimikatz and PsExec behavioral signatures.\n6. **Audit** AD replication permissions and restrict DCSync rights to only Domain Controllers.\n7. **Enable** Protected Users security group for all privileged and service accounts.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── BUILD ALL MOCK DATA ──────────────────────────────────────────────────────

// ─── USER002 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset2/user002logs.json
// Campaign: Multi-Stage Credential Access & Data Exfiltration — 91% CRITICAL

function buildUser002Dataset() {
  // ---------- Analysis ----------
  const analysis: MockAnalysis = {
    scan_id: "user-002",
    file_name: "user002logs.csv",
    total_logs: 10000,
    total_threats: 95,
    attack_chain_count: 4,
    risk_score: 9100,
    threat_density: 0.95,
    generated_at: "2026-04-06T11:43:31Z",
    status: "completed",
  }

  // ---------- Findings ----------
  const findings: MockFinding[] = [
    // Chain 1 — PowerShell Dropper → LSASS → PtH → C2
    { id: "fnd-u002-01", severity: "critical", title: "PowerShell Encoded IEX Download — Stage 1 Dropper", detection_type: "rule", rule_id: "SOC-T1059-001-002", mitre_techniques: ["PowerShell Encoded Command Execution"], mitre_ids: ["T1059.001"], affected_users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User1", "WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 30, description: "Eight encoded PowerShell IEX Download Cradle executions detected across PROD-01 and PROD-02 within 7 seconds, consistent with a staged dropper delivering a credential harvesting payload.", timestamp: "2026-04-02 00:02:07" },
    { id: "fnd-u002-02", severity: "critical", title: "LSASS Memory Dump via Mimikatz (3x)", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-002", mitre_techniques: ["OS Credential Dumping: LSASS Memory"], mitre_ids: ["T1003.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], count: 30, description: "ML model detected mimikatz.exe accessing LSASS memory on three separate occasions (NTLM hashes, Wdigest plaintext passwords). 9.4-sigma deviation from process access baseline.", timestamp: "2026-04-02 00:02:57" },
    { id: "fnd-u002-03", severity: "critical", title: "Pass-the-Hash — NTLM Type 3 Logon with Harvested Hash", detection_type: "behavioral", rule_id: "SOC-T1550-002-002", mitre_techniques: ["Use Alternate Authentication Material: Pass the Hash"], mitre_ids: ["T1550.002"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01"], count: 10, description: "Behavioral analysis detected NTLM network logon (Type 3) from win-soc-prod-02 to prod-01 using a harvested hash. NTLM was negotiated without Kerberos — canonical Pass-the-Hash indicator.", timestamp: "2026-04-02 00:04:00" },
    { id: "fnd-u002-04", severity: "critical", title: "HTTPS C2 Beacon — beacon.exe to 91.195.240.100:443", detection_type: "rule", rule_id: "SOC-T1071-001-002", mitre_techniques: ["Application Layer Protocol: Web Protocols"], mitre_ids: ["T1071.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], count: 8, description: "Unsigned beacon.exe established outbound HTTPS connections to 91.195.240.100:443 — an ASN associated with bulletproof hosting. Repeated heartbeat check-ins every 30 seconds detected.", timestamp: "2026-04-02 00:04:30" },
    // Chain 2 — WMI Lateral → Token Impersonation → Discovery
    { id: "fnd-u002-05", severity: "critical", title: "WMI Remote Execution — Lateral Movement to WIN-SOC-PROD-01", detection_type: "rule", rule_id: "SOC-T1047-002", mitre_techniques: ["Windows Management Instrumentation"], mitre_ids: ["T1047"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 12, description: "wmiprvse.exe spawned cmd.exe on WIN-SOC-PROD-01 via remote WMI invocation from PROD-02. A WMI event subscription was also created for persistent remote execution.", timestamp: "2026-04-02 00:15:00" },
    { id: "fnd-u002-06", severity: "critical", title: "Token Impersonation — SeImpersonatePrivilege Escalation", detection_type: "behavioral", rule_id: "SOC-T1134-001-002", mitre_techniques: ["Access Token Manipulation: Token Impersonation/Theft"], mitre_ids: ["T1134.001"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01"], count: 5, description: "Behavioral engine flagged Invoke-TokenManipulation execution escalating from Admin to SYSTEM-level token. SeImpersonatePrivilege subsequently assigned via lsass.exe logon event 4672.", timestamp: "2026-04-02 00:16:40" },
    { id: "fnd-u002-07", severity: "high", title: "WMI Event Subscription for Persistence", detection_type: "yara_match", rule_id: "SOC-T1546-003-001", mitre_techniques: ["Event Triggered Execution: WMI Event Subscription"], mitre_ids: ["T1546.003"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01"], count: 3, description: "YARA rule WMI_PERSIST_v2 matched wmiprvse.exe creating a permanent WMI subscription — a fileless persistence technique that survives reboots without writing files to disk.", timestamp: "2026-04-02 00:15:45" },
    { id: "fnd-u002-08", severity: "high", title: "Internal Network Discovery — ARP & Domain Host Enumeration", detection_type: "heuristic", rule_id: "SOC-T1018-002", mitre_techniques: ["Remote System Discovery", "System Information Discovery"], mitre_ids: ["T1018", "T1082"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01"], count: 4, description: "Heuristic engine flagged rapid sequential discovery commands: whoami /priv → arp -a → net view /domain within 90 seconds. Classic post-exploitation environment mapping pattern.", timestamp: "2026-04-02 00:16:10" },
    // Chain 3 — Registry Persistence → DLL Sideloading → Defense Evasion
    { id: "fnd-u002-09", severity: "high", title: "Registry Run Key + Startup Folder Persistence", detection_type: "rule", rule_id: "SOC-T1547-001-002", mitre_techniques: ["Boot or Logon Autostart Execution: Registry Run Keys"], mitre_ids: ["T1547.001"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-PROD-03"], count: 15, description: "reg.exe wrote UpdateSvc to HKCU Run key and dropped svchost_update.exe to the Startup folder — dual persistence mechanisms for cross-reboot survival on WIN-SOC-PROD-03.", timestamp: "2026-04-02 00:28:00" },
    { id: "fnd-u002-10", severity: "critical", title: "DLL Sideloading — version.dll via Malicious svchost Lookalike", detection_type: "yara_match", rule_id: "SOC-T1574-002-002", mitre_techniques: ["Hijack Execution Flow: DLL Side-Loading"], mitre_ids: ["T1574.002"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-PROD-03"], count: 6, description: "YARA rule DLL_SIDELOAD_SVCHOST matched svchost_update.exe loading unsigned version.dll from a non-standard path. Classic DLL sideloading to hijack legitimate process identity for defense evasion.", timestamp: "2026-04-02 00:29:00" },
    { id: "fnd-u002-11", severity: "high", title: "Windows Defender Disabled — sc.exe + PowerShell AV Bypass", detection_type: "behavioral", rule_id: "SOC-T1562-001-002", mitre_techniques: ["Impair Defenses: Disable or Modify Tools"], mitre_ids: ["T1562.001"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-PROD-03"], count: 7, description: "Two-step AV disablement: sc.exe stopped WinDefend service followed by Set-MpPreference -DisableRealtimeMonitoring $true via PowerShell. Both methods used to ensure Defender cannot restart.", timestamp: "2026-04-02 00:30:00" },
    // Chain 4 — Data Discovery → Staging → Compression → HTTPS Exfil
    { id: "fnd-u002-12", severity: "high", title: "Finance Share Discovery & Sensitive File Access", detection_type: "heuristic", rule_id: "SOC-T1083-002", mitre_techniques: ["File and Directory Discovery", "Data from Local System"], mitre_ids: ["T1083", "T1005"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 5, description: "Heuristic engine flagged recursive Get-ChildItem scan on the Finance share followed by direct reads of finance_q1_2026.xlsx and payroll_march.csv — sensitive financial data targeted for exfiltration.", timestamp: "2026-04-02 00:45:00" },
    { id: "fnd-u002-13", severity: "critical", title: "Data Staging — Robocopy + 7-Zip Password Archive (staging.7z)", detection_type: "ml_anomaly", rule_id: "SOC-T1074-001-002", mitre_techniques: ["Data Staged: Local Data Staging", "Archive Collected Data: Archive via Utility"], mitre_ids: ["T1074.001", "T1560.001"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 10, description: "ML model flagged 55 MB/s robocopy transfer to a temp staging directory (7.5-sigma I/O anomaly), followed by 7z.exe creating a password-protected archive (staging.7z) — pre-exfiltration data preparation.", timestamp: "2026-04-02 00:46:00" },
    { id: "fnd-u002-14", severity: "critical", title: "HTTPS Exfiltration + Evidence Cleanup", detection_type: "rule", rule_id: "SOC-T1041-002", mitre_techniques: ["Exfiltration Over C2 Channel", "Indicator Removal: File Deletion"], mitre_ids: ["T1041", "T1070.004"], affected_users: ["WIN-SOC\\SvcBuild"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 8, description: "PowerShell uploaded staging.7z over HTTPS to 185.62.188.250:443 in two batches (95 MB/s + 88 MB/s peak). Post-exfiltration, cmd.exe deleted the entire staging directory to eliminate forensic evidence.", timestamp: "2026-04-02 00:47:30" },
  ]

  // ---------- Attack Chains ----------
  const chains: MockChain[] = [
    {
      chain_id: "chain-ds-002-01",
      chain_index: 1,
      title: "PowerShell Dropper → LSASS Dump → Pass-the-Hash → C2",
      computer: "WIN-SOC-PROD-02",
      chain_confidence: 0.98,
      kill_chain_phases: ["execution", "credential-access", "lateral-movement", "command-and-control"],
      affected_users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User1", "WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"],
      events: ["fnd-ds-002-log-1", "fnd-ds-002-log-9", "fnd-ds-002-log-12", "fnd-ds-002-log-13"],
    },
    {
      chain_id: "chain-ds-002-02",
      chain_index: 2,
      title: "WMI Lateral Movement → Token Impersonation → Internal Discovery",
      computer: "WIN-SOC-PROD-01",
      chain_confidence: 0.96,
      kill_chain_phases: ["lateral-movement", "persistence", "privilege-escalation", "discovery"],
      affected_users: ["WIN-SOC\\Admin"],
      affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"],
      events: ["fnd-ds-002-log-15", "fnd-ds-002-log-17", "fnd-ds-002-log-19", "fnd-ds-002-log-21"],
    },
    {
      chain_id: "chain-ds-002-03",
      chain_index: 3,
      title: "Registry & Startup Persistence → DLL Sideloading → Defense Evasion",
      computer: "WIN-SOC-PROD-03",
      chain_confidence: 0.94,
      kill_chain_phases: ["persistence", "defense-evasion"],
      affected_users: ["WIN-SOC\\SvcBuild"],
      affected_hosts: ["WIN-SOC-PROD-03"],
      events: ["fnd-ds-002-log-23", "fnd-ds-002-log-25", "fnd-ds-002-log-27"],
    },
    {
      chain_id: "chain-ds-002-04",
      chain_index: 4,
      title: "File Share Discovery → Data Staging → HTTPS Exfiltration & Cleanup",
      computer: "WIN-SOC-FILESVR-01",
      chain_confidence: 0.97,
      kill_chain_phases: ["discovery", "collection", "exfiltration", "defense-evasion"],
      affected_users: ["WIN-SOC\\SvcBuild"],
      affected_hosts: ["WIN-SOC-FILESVR-01"],
      events: ["fnd-ds-002-log-29", "fnd-ds-002-log-31", "fnd-ds-002-log-33", "fnd-ds-002-log-35"],
    },
  ]

  // ---------- Summary ----------
  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user002logs.csv |
| Generated On | 2026-04-06 11:43:31 UTC |
| Risk Level | 🔴 CRITICAL (91%) |
| Total Logs | 10,000 |
| Threat Events | 95 |
| Attack Chains | 4 |
| Affected Hosts | 4 |
| Affected Users | 5 |

---

## 🧠 2. EXECUTIVE SUMMARY
A multi-stage **credential-focused threat campaign** was detected in **user002logs.csv** spanning **4 distinct attack chains** across 8 MITRE ATT&CK tactic categories.

Primary attack vectors: LSASS Memory Dump, WMI-based Lateral Movement, Token Impersonation, Registry & Startup Persistence, DLL Sideloading, and HTTPS-based Financial Data Exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01**
- **WIN-SOC-PROD-02**
- **WIN-SOC-PROD-03**
- **WIN-SOC-FILESVR-01**

Immediate containment and forensic investigation is required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-02 00:02:07 | WIN-SOC-PROD-02 | Encoded IEX Download — Stage 1 Dropper |
| 2026-04-02 00:02:57 | WIN-SOC-PROD-02 | LSASS Memory Dump via Mimikatz (Attempt 1) |
| 2026-04-02 00:03:11 | WIN-SOC-PROD-02 | Mimikatz LSASS Dump #3 — Wdigest Plaintext |
| 2026-04-02 00:04:00 | WIN-SOC-PROD-01 | Pass-the-Hash Logon with Harvested Hash |
| 2026-04-02 00:04:30 | WIN-SOC-PROD-02 | C2 Beacon Established to 91.195.240.100:443 |
| 2026-04-02 00:15:00 | WIN-SOC-PROD-01 | WMI Remote Execution — Lateral Movement |
| 2026-04-02 00:16:40 | WIN-SOC-PROD-01 | Token Impersonation → SYSTEM Escalation |
| 2026-04-02 00:28:00 | WIN-SOC-PROD-03 | Registry Run Key + Startup Folder Persistence |
| 2026-04-02 00:29:00 | WIN-SOC-PROD-03 | DLL Sideloading via svchost_update.exe |
| 2026-04-02 00:30:00 | WIN-SOC-PROD-03 | Windows Defender Disabled |
| 2026-04-02 00:45:00 | WIN-SOC-FILESVR-01 | Finance Share Discovery & File Access |
| 2026-04-02 00:46:45 | WIN-SOC-FILESVR-01 | 7-Zip Password Archive Created (staging.7z) |
| 2026-04-02 00:47:30 | WIN-SOC-FILESVR-01 | HTTPS Exfiltration to 185.62.188.250:443 |
| 2026-04-02 00:48:30 | WIN-SOC-FILESVR-01 | Staging Directory Deleted — Evidence Cleanup |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** PowerShell Encoded Dropper → Mimikatz LSASS Dump → Pass-the-Hash → HTTPS C2 Beacon
- **Chain 2:** WMI Remote Execution → WMI Persistence Subscription → Token Impersonation → Internal Discovery
- **Chain 3:** Registry Run Key + Startup Folder → DLL Sideloading (version.dll) → AV Disabled
- **Chain 4:** Finance Share Discovery → Robocopy Staging → 7-Zip Archive → HTTPS Exfiltration → Evidence Cleanup

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |
| T1071.001 | Application Layer Protocol: Web Protocols (HTTPS C2) | Command & Control |
| T1047 | Windows Management Instrumentation | Lateral Movement |
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistence |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Privilege Escalation |
| T1082 | System Information Discovery | Discovery |
| T1018 | Remote System Discovery | Discovery |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Defense Evasion |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion |
| T1083 | File and Directory Discovery | Discovery |
| T1005 | Data from Local System | Collection |
| T1074.001 | Data Staged: Local Data Staging | Collection |
| T1560.001 | Archive Collected Data: Archive via Utility | Collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | LSASS Memory Dump (Mimikatz ×3) | 30 |
| 🔴 CRITICAL | Pass-the-Hash Lateral Movement | 10 |
| 🔴 CRITICAL | WMI Remote Execution | 12 |
| 🔴 CRITICAL | Data Staging → 7-Zip Archive | 10 |
| 🔴 CRITICAL | HTTPS Exfiltration + Evidence Cleanup | 8 |
| 🔴 CRITICAL | DLL Sideloading (version.dll) | 6 |
| 🟠 HIGH | Registry + Startup Persistence | 15 |
| 🟠 HIGH | WMI Event Subscription (Fileless Persist) | 3 |
| 🟠 HIGH | AV Disabled (sc.exe + PowerShell) | 7 |
| 🟠 HIGH | Finance Share File Access | 5 |
| 🟡 MEDIUM | Token Impersonation / SeImpersonate | 5 |
| 🟡 MEDIUM | Internal Host Discovery (ARP, net view) | 4 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — WMI lateral movement target, token impersonation, internal recon
- WIN-SOC-PROD-02 — Initial compromise, LSASS dump, C2 beacon origin
- WIN-SOC-PROD-03 — Registry/Startup persistence, DLL sideloading, AV disabled
- WIN-SOC-FILESVR-01 — Finance data discovery, staging, exfiltration origin

**Users**
- WIN-SOC\\Dev-01
- WIN-SOC\\User1
- WIN-SOC\\Admin
- WIN-SOC\\SvcBuild
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Enable Credential Guard** on all domain endpoints to block LSASS memory access by non-system processes
- **Isolate all 4 affected hosts** immediately and revoke credentials for Dev-01, User1, Admin, SvcBuild
- **Restrict WMI remote access** via Windows Firewall GPO (block DCOM port 135 from non-admin sources)
- **Audit and remove** unauthorized registry Run keys and Startup folder binaries across all endpoints
- **Monitor outbound HTTPS** for large data transfers (>10MB) to unclassified external IPs
- **Deploy DLL monitoring** and application whitelisting — block unsigned DLLs from non-standard paths
- **Alert on archive creation** (7z, zip, rar) in user temp and AppData directories
- **Block beacon.exe and svchost_update.exe** via EDR hash-based blocking immediately

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 91% (CRITICAL)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | CRITICAL |
| Confidence | 97% |
`

  const summary: MockSummary = {
    scan_id: "user-002",
    generated_at: "2026-04-06T11:43:31Z",
    executive_briefing: "A CRITICAL multi-stage credential-focused threat campaign was detected in user002logs.csv. Analysis identified 95 threat events across 4 hosts and 4 attack chains. Primary vectors: LSASS Credential Dumping, WMI Lateral Movement, Token Impersonation, Registry & DLL Sideloading Persistence, and HTTPS-based Financial Data Exfiltration. Immediate containment and forensic investigation required.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A CRITICAL credential-focused APT campaign was detected in user002logs.csv spanning 4 attack chains. Techniques: LSASS Dump (T1003.001), Pass-the-Hash (T1550.002), WMI Lateral Movement (T1047), Token Impersonation (T1134.001), DLL Sideloading (T1574.002), Registry Persistence (T1547.001), and HTTPS Exfiltration (T1041) of financial data from WIN-SOC-FILESVR-01. Risk Score: 91% CRITICAL.",
      attack_narrative: "Between 2026-04-02 00:02 UTC and 00:48 UTC, a threat actor executed a 4-chain credential-focused campaign. Encoded PowerShell dropped Mimikatz, which extracted NTLM hashes from LSASS. Pass-the-Hash enabled lateral movement to PROD-01. WMI remote execution spread to additional hosts with fileless WMI persistence. Token impersonation escalated to SYSTEM. On PROD-03, registry + startup persistence and DLL sideloading were established, with Defender disabled. Sensitive financial files were staged, archived with 7-Zip, and exfiltrated over HTTPS to 185.62.188.250, followed by evidence deletion.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01, WIN-SOC-PROD-02, WIN-SOC-PROD-03, WIN-SOC-FILESVR-01\n\n**Users:** WIN-SOC\\Dev-01, WIN-SOC\\User1, WIN-SOC\\Admin, WIN-SOC\\SvcBuild, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Enable Credential Guard** on all domain endpoints to prevent LSASS access.\n2. **Reset credentials** for all 5 compromised accounts immediately.\n3. **Block WMI remote execution** (DCOM port 135) via GPO firewall rules.\n4. **Remove** unauthorized registry Run keys and Startup folder binaries on PROD-03.\n5. **Block outbound HTTPS** to 91.195.240.100 and 185.62.188.250 immediately.\n6. **Scan all endpoints** for unsigned DLLs loaded from non-standard paths.\n7. **Review file server access logs** for additional financial data access.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER003 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset3/user003logs.json
// Campaign: Multi-Vector APT — 6 attack chains, 97% CRITICAL

function buildUser003Dataset() {
  // ---------- Analysis ----------
  const analysis: MockAnalysis = {
    scan_id: "user-003",
    file_name: "user003logs.csv",
    total_logs: 10000,
    total_threats: 120,
    attack_chain_count: 6,
    risk_score: 9700,
    threat_density: 1.2,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  // ---------- Findings (derived from user003logs.json attacked_logs) ----------
  const findings: MockFinding[] = [
    // Chain 1 — Lateral Movement via SMB + LSASS Dump
    { id: "fnd-u003-01", severity: "critical", title: "PowerShell Encoded IEX Download — Lateral Movement Entry", detection_type: "rule", rule_id: "SOC-T1059-001-003", mitre_techniques: ["PowerShell Encoded Command Execution"], mitre_ids: ["T1059.001"], affected_users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User1", "WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "Five encoded PowerShell IEX Download Cradle executions detected across PROD-01 and PROD-02 within 4 seconds — consistent with an automated stage-1 dropper delivering a lateral movement payload via SMB Admin shares.", timestamp: "2026-03-26 23:56:48" },
    { id: "fnd-u003-02", severity: "critical", title: "LSASS Memory Dump via Mimikatz (2 hosts)", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-003", mitre_techniques: ["OS Credential Dumping: LSASS Memory"], mitre_ids: ["T1003.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "ML model detected mimikatz.exe accessing LSASS memory on both PROD-01 and PROD-02, extracting NTLM hashes. Network I/O spike to 90 MB/s — 9.3-sigma deviation. Dump confirms full credential harvesting.", timestamp: "2026-03-26 23:57:38" },
    // Chain 2 — Spearphishing → Macro Execution → Persistence
    { id: "fnd-u003-03", severity: "high", title: "Spearphishing Attachment — Macro Execution on WIN-SOC-PROD-03", detection_type: "yara_match", rule_id: "SOC-T1566-001-003", mitre_techniques: ["Phishing: Spearphishing Attachment", "User Execution: Malicious File"], mitre_ids: ["T1566.001", "T1204.002"], affected_users: ["WIN-SOC\\Analyst1"], affected_hosts: ["WIN-SOC-PROD-03"], count: 15, description: "YARA rule MACRO_DROPPER_v3 matched. Analyst1 opened a malicious email attachment triggering a VBA macro in winword.exe that spawned cmd.exe — classic Office macro shellcode dropper pattern.", timestamp: "2026-03-27 01:10:05" },
    { id: "fnd-u003-04", severity: "critical", title: "Malicious Scheduled Task + Service Installed for Persistence", detection_type: "behavioral", rule_id: "SOC-T1053-T1543-003", mitre_techniques: ["Scheduled Task/Job", "Create or Modify System Process: Windows Service"], mitre_ids: ["T1053.005", "T1543.003"], affected_users: ["WIN-SOC\\Analyst1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-03"], count: 10, description: "Behavioral engine flagged dual persistence: schtasks.exe created a malicious scheduled task, then services.exe installed an unsigned malicious service — ensuring cross-reboot persistence on PROD-03.", timestamp: "2026-03-27 01:10:45" },
    // Chain 3 — DLL Injection + Privilege Escalation + Defense Evasion
    { id: "fnd-u003-05", severity: "critical", title: "DLL Injection into svchost.exe — Privilege Escalation", detection_type: "rule", rule_id: "SOC-T1055-001-003", mitre_techniques: ["Process Injection: Dynamic-link Library Injection"], mitre_ids: ["T1055.001"], affected_users: ["WIN-SOC\\SvcAcct"], affected_hosts: ["WIN-SOC-PROD-04"], count: 10, description: "rundll32.exe injected an unsigned DLL into svchost.exe (Sysmon Event 8: CreateRemoteThread) followed by SeDebugPrivilege abuse — escalating from SvcAcct to SYSTEM on PROD-04.", timestamp: "2026-03-27 02:05:00" },
    { id: "fnd-u003-06", severity: "critical", title: "Windows Event Log Clearing — Audit Trail Destruction", detection_type: "behavioral", rule_id: "SOC-T1070-001-003", mitre_techniques: ["Indicator Removal: Clear Windows Event Logs"], mitre_ids: ["T1070.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], count: 10, description: "wevtutil.exe used to clear all Windows Event Logs (event 4688) followed by the audit log deletion (event 1102) — destroying forensic evidence post-privilege-escalation. SYSTEM-level execution confirms full compromise.", timestamp: "2026-03-27 02:07:10" },
    // Chain 4 — Credential Harvesting via ProcDump + Pass-the-Hash
    { id: "fnd-u003-07", severity: "critical", title: "LSASS Dump via ProcDump + NTLM Hash Extraction", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-004", mitre_techniques: ["OS Credential Dumping: LSASS Memory"], mitre_ids: ["T1003.001"], affected_users: ["WIN-SOC\\BackupOp", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-05"], count: 15, description: "ML model flagged procdump.exe accessing LSASS virtual memory — 9.7-sigma anomaly. CPU spike to 72%, Network I/O 95 MB/s. NTLM hash extracted (event 4776), followed by SAM registry hive dump via reg.exe.", timestamp: "2026-03-27 03:15:00" },
    { id: "fnd-u003-08", severity: "critical", title: "Pass-the-Hash — Kerberos TGT Request from WIN-SOC-DC-01", detection_type: "behavioral", rule_id: "SOC-T1550-002-003", mitre_techniques: ["Use Alternate Authentication Material: Pass the Hash"], mitre_ids: ["T1550.002"], affected_users: ["WIN-SOC\\BackupOp"], affected_hosts: ["WIN-SOC-DC-01"], count: 5, description: "Behavioral analysis detected Kerberos TGT request (event 4768) from BackupOp using a harvested NTLM hash — Pass-the-Hash lateral movement to the domain controller confirmed.", timestamp: "2026-03-27 03:16:45" },
    // Chain 5 — C2 Beaconing + Tool Download
    { id: "fnd-u003-09", severity: "critical", title: "HTTPS C2 Beacon + DNS Tunneling to 185.220.101.42", detection_type: "rule", rule_id: "SOC-T1071-001-003", mitre_techniques: ["Application Layer Protocol: Web Protocols", "Application Layer Protocol: DNS"], mitre_ids: ["T1071.001", "T1071.004"], affected_users: ["WIN-SOC\\DBAdmin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-06"], count: 15, description: "DBAdmin's powershell.exe established repeated HTTPS beaconing to 185.220.101.42:443 (bulletproof ASN). DNS tunneling C2 also detected (Sysmon event 3). certutil.exe then downloaded a secondary payload — keylogger dropped.", timestamp: "2026-03-27 04:00:10" },
    // Chain 6 — Data Staging + FTP + HTTPS Exfiltration
    { id: "fnd-u003-10", severity: "critical", title: "Data Staging via robocopy + 7-Zip Password Archive", detection_type: "ml_anomaly", rule_id: "SOC-T1074-001-003", mitre_techniques: ["Data Staged: Local Data Staging", "Archive Collected Data: Archive via Utility"], mitre_ids: ["T1074.001", "T1560.001"], affected_users: ["WIN-SOC\\DBAdmin"], affected_hosts: ["WIN-SOC-PROD-06"], count: 10, description: "ML model flagged 120 MB/s robocopy bulk file copy to a staging directory (8.1-sigma I/O anomaly), followed by 7z.exe creating a password-protected archive. CPU 60%, Mem 850 MB — clear pre-exfiltration staging pattern.", timestamp: "2026-03-27 05:30:00" },
    { id: "fnd-u003-11", severity: "critical", title: "Dual-Channel Exfiltration — FTP + HTTPS POST to 91.108.4.10", detection_type: "rule", rule_id: "SOC-T1041-003", mitre_techniques: ["Exfiltration Over C2 Channel"], mitre_ids: ["T1041"], affected_users: ["WIN-SOC\\DBAdmin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-06", "WIN-SOC-DC-01"], count: 15, description: "Data exfiltrated over dual channels: ftp.exe (event 5156, 200 MB/s) and powershell.exe HTTPS POST (190 MB/s) to 91.108.4.10. DBAdmin then accessed SYSVOL share on DC-01 for additional credential/GPO file exfiltration.", timestamp: "2026-03-27 05:31:30" },
    // Additional HIGH/MEDIUM findings
    { id: "fnd-u003-12", severity: "high", title: "SAM Registry Hive Dump via reg.exe", detection_type: "behavioral", rule_id: "SOC-T1003-002-003", mitre_techniques: ["OS Credential Dumping: Security Account Manager"], mitre_ids: ["T1003.002"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-05"], count: 5, description: "reg.exe saved the SAM registry hive to disk — exposing local account credentials. Combined with LSASS dump, attacker obtained complete local and domain credential material.", timestamp: "2026-03-27 03:17:30" },
    { id: "fnd-u003-13", severity: "high", title: "Certutil Ingress Tool Transfer — Payload Downloaded", detection_type: "heuristic", rule_id: "SOC-T1105-003", mitre_techniques: ["Ingress Tool Transfer"], mitre_ids: ["T1105"], affected_users: ["WIN-SOC\\DBAdmin"], affected_hosts: ["WIN-SOC-PROD-06"], count: 4, description: "certutil.exe used to download a secondary payload from the C2 server — a living-off-the-land (LOLBAS) technique to bypass application whitelisting and download additional attack tools.", timestamp: "2026-03-27 04:02:00" },
    { id: "fnd-u003-14", severity: "high", title: "Unauthorized SYSVOL Share Access on Domain Controller", detection_type: "heuristic", rule_id: "SOC-T1041-SYSVOL-003", mitre_techniques: ["Exfiltration Over C2 Channel"], mitre_ids: ["T1041"], affected_users: ["WIN-SOC\\DBAdmin"], affected_hosts: ["WIN-SOC-DC-01"], count: 3, description: "DBAdmin accessed the SYSVOL share on WIN-SOC-DC-01 (event 5140) via explorer.exe — unauthorized access to Group Policy files and scripts, enabling further privilege escalation and lateral movement.", timestamp: "2026-03-27 05:33:00" },
  ]

  // ---------- Attack Chains (from user003logs.json attack_chains) ----------
  const chains: MockChain[] = [
    {
      chain_id: "chain-ds-003-01",
      chain_index: 1,
      title: "Lateral Movement via SMB + LSASS Credential Dump",
      computer: "WIN-SOC-PROD-01",
      chain_confidence: 0.97,
      kill_chain_phases: ["execution", "lateral-movement", "credential-access"],
      affected_users: ["WIN-SOC\\Dev-01", "NT AUTHORITY\\SYSTEM", "WIN-SOC\\User1", "WIN-SOC\\Admin"],
      affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"],
      events: ["fnd-ds-003-log-1", "fnd-ds-003-log-2", "fnd-ds-003-log-3", "fnd-ds-003-log-4", "fnd-ds-003-log-5", "fnd-ds-003-log-6", "fnd-ds-003-log-7"],
    },
    {
      chain_id: "chain-ds-003-02",
      chain_index: 2,
      title: "Spearphishing → Office Macro → Scheduled Task + Service Persistence",
      computer: "WIN-SOC-PROD-03",
      chain_confidence: 0.95,
      kill_chain_phases: ["initial-access", "execution", "persistence"],
      affected_users: ["WIN-SOC\\Analyst1", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-03"],
      events: ["fnd-ds-003-log-8", "fnd-ds-003-log-9", "fnd-ds-003-log-10", "fnd-ds-003-log-11", "fnd-ds-003-log-12"],
    },
    {
      chain_id: "chain-ds-003-03",
      chain_index: 3,
      title: "DLL Injection → SeDebugPrivilege Escalation → Event Log Clearing",
      computer: "WIN-SOC-PROD-04",
      chain_confidence: 0.96,
      kill_chain_phases: ["privilege-escalation", "defense-evasion"],
      affected_users: ["WIN-SOC\\SvcAcct", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-04"],
      events: ["fnd-ds-003-log-13", "fnd-ds-003-log-14", "fnd-ds-003-log-15", "fnd-ds-003-log-16", "fnd-ds-003-log-17"],
    },
    {
      chain_id: "chain-ds-003-04",
      chain_index: 4,
      title: "Credential Harvesting via ProcDump + SAM Dump + Pass-the-Hash",
      computer: "WIN-SOC-PROD-05",
      chain_confidence: 0.98,
      kill_chain_phases: ["credential-access", "lateral-movement"],
      affected_users: ["WIN-SOC\\BackupOp", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-05", "WIN-SOC-DC-01"],
      events: ["fnd-ds-003-log-18", "fnd-ds-003-log-19", "fnd-ds-003-log-20", "fnd-ds-003-log-21", "fnd-ds-003-log-22"],
    },
    {
      chain_id: "chain-ds-003-05",
      chain_index: 5,
      title: "C2 HTTPS Beacon + DNS Tunneling + Ingress Tool Transfer",
      computer: "WIN-SOC-PROD-06",
      chain_confidence: 0.97,
      kill_chain_phases: ["command-and-control", "execution"],
      affected_users: ["WIN-SOC\\DBAdmin", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-06"],
      events: ["fnd-ds-003-log-23", "fnd-ds-003-log-24", "fnd-ds-003-log-25", "fnd-ds-003-log-26", "fnd-ds-003-log-27"],
    },
    {
      chain_id: "chain-ds-003-06",
      chain_index: 6,
      title: "Data Staging via robocopy → 7-Zip Archive → FTP + HTTPS Exfiltration",
      computer: "WIN-SOC-PROD-06",
      chain_confidence: 0.99,
      kill_chain_phases: ["collection", "exfiltration"],
      affected_users: ["WIN-SOC\\DBAdmin", "NT AUTHORITY\\SYSTEM"],
      affected_hosts: ["WIN-SOC-PROD-06", "WIN-SOC-DC-01"],
      events: ["fnd-ds-003-log-28", "fnd-ds-003-log-29", "fnd-ds-003-log-30", "fnd-ds-003-log-31", "fnd-ds-003-log-32"],
    },
  ]

  // ---------- Summary (derived from user003logs.json ai_summary_report) ----------
  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user003logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🔴 CRITICAL (97%) |
| Total Logs | 10,000 |
| Threat Events | 120 |
| Attack Chains | 6 |
| Affected Hosts | 6 |
| Affected Users | 8 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **multi-vector critical threat campaign** was detected in **user003logs.csv** spanning **6 distinct attack chains** across 10 MITRE ATT&CK tactic categories.

Primary attack vectors: PowerShell Encoded Command Execution, LSASS Memory Dumping (Mimikatz + ProcDump), Spearphishing-driven Initial Access, DLL Injection with Privilege Escalation, Event Log Clearing, Pass-the-Hash Lateral Movement, C2 Beaconing via HTTPS & DNS Tunneling, and Dual-Channel Data Exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01**
- **WIN-SOC-PROD-02**
- **WIN-SOC-PROD-03**
- **WIN-SOC-PROD-04**
- **WIN-SOC-PROD-05**
- **WIN-SOC-PROD-06**
- **WIN-SOC-DC-01**

Immediate containment and forensic investigation is required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-03-26 23:56:48 | WIN-SOC-PROD-01 | Encoded IEX Download (PowerShell C2) |
| 2026-03-26 23:57:38 | WIN-SOC-PROD-01/02 | LSASS Memory Dump (mimikatz.exe) |
| 2026-03-27 01:10:05 | WIN-SOC-PROD-03 | Spearphishing Email Opened — Macro Execution |
| 2026-03-27 01:10:45 | WIN-SOC-PROD-03 | Malicious Scheduled Task + Service Installed |
| 2026-03-27 02:05:00 | WIN-SOC-PROD-04 | DLL Injection into svchost.exe |
| 2026-03-27 02:07:10 | WIN-SOC-PROD-04 | Windows Event Logs Cleared (wevtutil) |
| 2026-03-27 03:15:30 | WIN-SOC-PROD-05 | LSASS Dump via ProcDump + SAM Hive Dump |
| 2026-03-27 03:16:45 | WIN-SOC-DC-01 | Pass-the-Hash Kerberos TGT Request |
| 2026-03-27 04:00:10 | WIN-SOC-PROD-06 | HTTPS C2 Beacon + DNS Tunneling |
| 2026-03-27 04:02:00 | WIN-SOC-PROD-06 | certutil Payload Download (Keylogger) |
| 2026-03-27 05:30:00 | WIN-SOC-PROD-06 | Data Staging via robocopy + 7-Zip Archive |
| 2026-03-27 05:31:30 | WIN-SOC-PROD-06 | FTP + HTTPS Exfiltration to 91.108.4.10 |
| 2026-03-27 05:33:00 | WIN-SOC-DC-01 | Unauthorized SYSVOL Share Access |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** PowerShell Encoded Dropper → SMB Lateral Movement → LSASS Credential Dump (Mimikatz)
- **Chain 2:** Spearphishing Attachment → Office Macro → Scheduled Task + Malicious Service (Persistence)
- **Chain 3:** DLL Injection into svchost → SeDebugPrivilege Escalation → Event Log + Audit Trail Clearing
- **Chain 4:** Explicit Cred Logon → ProcDump LSASS → NTLM Hash → Pass-the-Hash → SAM Hive Dump
- **Chain 5:** HTTPS C2 Beacon → DNS Tunneling → certutil Ingress Tool Transfer → Keylogger Dropped
- **Chain 6:** robocopy Data Staging → 7-Zip Password Archive → FTP Exfil → HTTPS POST Exfil → SYSVOL Access

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1053.005 | Scheduled Task | Persistence |
| T1543.003 | Windows Service Installation | Persistence |
| T1055.001 | DLL Injection into svchost | Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation (SeDebugPrivilege) | Privilege Escalation |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1003.001 | LSASS Memory Dump | Credential Access |
| T1003.002 | SAM Registry Hive Dump | Credential Access |
| T1550.002 | Pass the Hash | Lateral Movement |
| T1021.002 | SMB Admin Share | Lateral Movement |
| T1071.001 | C2 via HTTPS Beacon | Command & Control |
| T1071.004 | DNS Tunneling | Command & Control |
| T1105 | Ingress Tool Transfer via certutil | Command & Control |
| T1074.001 | Local Data Staging | Collection |
| T1560.001 | Archive Collected Data (7-Zip) | Collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | LSASS Credential Dumping (Mimikatz + ProcDump) | 20 |
| 🔴 CRITICAL | Lateral Movement via SMB Admin Share | 20 |
| 🔴 CRITICAL | Exfiltration Over C2 Channel (FTP + HTTPS) | 15 |
| 🔴 CRITICAL | DLL Injection + Privilege Escalation | 10 |
| 🔴 CRITICAL | Data Staging + 7-Zip Archive | 10 |
| 🟠 HIGH | Spearphishing Attachment + Macro | 15 |
| 🟠 HIGH | PowerShell Encoded Execution | 20 |
| 🟠 HIGH | Scheduled Task + Service Persistence | 10 |
| 🟡 MEDIUM | DLL Injection + Event Log Clearing | 10 |
| 🟡 MEDIUM | SAM Registry Hive Dump | 5 |
| 🟡 MEDIUM | certutil Ingress Tool Transfer | 4 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — PowerShell dropper, LSASS dump source
- WIN-SOC-PROD-02 — SMB lateral movement target, LSASS dump
- WIN-SOC-PROD-03 — Phishing initial access, scheduled task/service persistence
- WIN-SOC-PROD-04 — DLL injection, privilege escalation, event log clearing
- WIN-SOC-PROD-05 — ProcDump LSASS, SAM hive dump, Pass-the-Hash origin
- WIN-SOC-PROD-06 — C2 beacon, DNS tunneling, data staging, exfiltration
- WIN-SOC-DC-01 — Pass-the-Hash target, SYSVOL unauthorized access

**Users**
- WIN-SOC\\Dev-01
- WIN-SOC\\User1
- WIN-SOC\\Admin
- WIN-SOC\\Analyst1
- WIN-SOC\\SvcAcct
- WIN-SOC\\BackupOp
- WIN-SOC\\DBAdmin
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Isolate all 7 affected hosts** immediately from the network
- **Enable Credential Guard** on all endpoints to block LSASS memory access
- **Deploy macro execution policies** — disable Office VBA macros via GPO for non-admin users
- **Block certutil.exe** from making outbound network connections via AppLocker/WDAC
- **Monitor and alert** on wevtutil.exe event log clearing by non-audit processes
- **Restrict DLL loading** from non-standard paths using application whitelisting
- **Block outbound FTP and HTTPS** to 91.108.4.10 and 185.220.101.42 at perimeter
- **Audit SYSVOL and NETLOGON** share access logs for unauthorized reads
- **Reset all 8 compromised accounts** and enable Protected Users group for privileged accounts
- **Enable Script Block Logging** (Event ID 4104) and Sysmon process injection monitoring

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 97% (CRITICAL)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | CRITICAL |
| Confidence | 97% |
`

  const summary: MockSummary = {
    scan_id: "user-003",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A CRITICAL multi-vector APT campaign was detected in user003logs.csv. Analysis identified 120 threat events across 6 hosts, 7 affected computers, and 8 compromised accounts spanning 6 attack chains. Primary attack vectors: PowerShell Encoded Execution, LSASS/ProcDump Credential Dumping, Spearphishing + Macro Persistence, DLL Injection + Privilege Escalation, HTTPS/DNS C2 Beaconing, and Dual-Channel Data Exfiltration (FTP + HTTPS). Immediate containment required.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A CRITICAL multi-vector APT campaign was detected in user003logs.csv spanning 6 attack chains across 10 MITRE ATT&CK tactic categories. Techniques: PowerShell Encoded Execution (T1059.001), LSASS Dump (T1003.001), ProcDump + SAM Hive (T1003.002), Spearphishing (T1566.001), Scheduled Task/Service Persistence (T1053.005/T1543.003), DLL Injection (T1055.001), Event Log Clearing (T1070.001), Pass-the-Hash (T1550.002), C2 Beacon (T1071.001/T1071.004), certutil Download (T1105), Data Staging + 7-Zip (T1074.001/T1560.001), FTP+HTTPS Exfiltration (T1041). Risk Score: 97% CRITICAL.",
      attack_narrative: "Between 2026-03-26 23:56 UTC and 2026-03-27 05:33 UTC, a sophisticated threat actor executed a 6-chain multi-vector campaign. Chain 1 began with encoded PowerShell droppers on PROD-01/02 and mimikatz LSASS dumps. Chain 2 delivered a spearphishing macro on PROD-03 creating scheduled task and service persistence. Chain 3 used DLL injection on PROD-04 to escalate to SYSTEM and clear event logs. Chain 4 on PROD-05 used ProcDump to harvest LSASS credentials and Pass-the-Hash to target DC-01. Chain 5 on PROD-06 established HTTPS C2 with DNS tunneling and dropped a keylogger via certutil. Chain 6 staged data with robocopy, archived with 7-Zip, and exfiltrated via dual FTP + HTTPS channels to 91.108.4.10, culminating in unauthorized SYSVOL access on DC-01.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01, WIN-SOC-PROD-02, WIN-SOC-PROD-03, WIN-SOC-PROD-04, WIN-SOC-PROD-05, WIN-SOC-PROD-06, WIN-SOC-DC-01\n\n**Users:** WIN-SOC\\Dev-01, WIN-SOC\\User1, WIN-SOC\\Admin, WIN-SOC\\Analyst1, WIN-SOC\\SvcAcct, WIN-SOC\\BackupOp, WIN-SOC\\DBAdmin, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Isolate** all 7 affected hosts from the network immediately.\n2. **Reset credentials** for all 8 compromised accounts and enable Protected Users group.\n3. **Enable Credential Guard** on all domain endpoints to prevent future LSASS access.\n4. **Block** outbound connections to 185.220.101.42 and 91.108.4.10 at the perimeter firewall.\n5. **Disable VBA macros** via GPO and deploy YARA rules for macro dropper detection.\n6. **Monitor SYSVOL and NETLOGON** share access and restrict to Domain Controllers and authorized admin accounts.\n7. **Deploy Sysmon** with process injection and DLL monitoring rules across all endpoints.\n8. **Enable Script Block Logging** (Event ID 4104) to capture future encoded PowerShell payloads.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── BUILD ALL MOCK DATA ──────────────────────────────────────────────────────

const USER_UPLOAD_DATASET = buildUserUploadDataset()
const USER_001_DATASET = buildUser001Dataset()
const USER_002_DATASET = buildUser002Dataset()
const USER_003_DATASET = buildUser003Dataset()
export const MOCK_DATASETS = [...DATASET_META.map(buildMockDataset), USER_UPLOAD_DATASET, USER_001_DATASET, USER_002_DATASET, USER_003_DATASET]

// ─── LOOKUP HELPERS ───────────────────────────────────────────────────────────

// Scan IDs that belong to user-uploaded datasets \u2014 excluded from the pre-loaded list
const USER_UPLOAD_SCAN_IDS = new Set(["mock-upload-id", ...Object.values(USER_CSV_TO_SCAN_ID)])

export function getMockAnalysisList(): MockAnalysis[] {
  return MOCK_DATASETS.filter(d => !USER_UPLOAD_SCAN_IDS.has(d.analysis.scan_id)).map(d => d.analysis)
}

export function getMockAnalysis(id: string) {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id)?.analysis ?? null
}

export function getMockEvents(id: string): MockEvent[] {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id)?.events ?? []
}

export function getMockFindings(id: string): MockFinding[] {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id)?.findings ?? []
}

export function getMockChains(id: string): MockChain[] {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id)?.chains ?? []
}

export function getMockSummary(id: string): MockSummary | null {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id)?.summary ?? null
}

export function getMockCategories(id: string) {
  const findings = getMockFindings(id)
  return findings.map(f => ({
    tactic: f.mitre_ids[0] || "unknown",
    risk_score: f.severity === "critical" ? 9.5 : f.severity === "high" ? 7.5 : 5,
    event_count: f.count,
  }))
}

export function getMockFullData(id: string) {
  return MOCK_DATASETS.find(d => d.analysis.scan_id === id) || null
}
