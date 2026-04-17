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
  "user004logs.csv": "user-004",
  "user005logs.csv": "user-005",
  "user006logs.csv": "user-006",
  "user007logs.csv": "user-007",
  "user008logs.csv": "user-008",
  "user009logs.csv": "user-009",
  "user0010logs.csv": "user-0010",
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
  { id: "ds-001", file: "windows_soc_data_1_ee46.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], users: ["WIN-SOC\\Admin", "WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], riskScore: 8750, threatType: "PowerShell Encoded Command Execution", mitre: "T1059.001", mitrePhase: "execution",           totalThreats: 127, totalLogs: 45200 },
  { id: "ds-002", file: "windows_soc_data_2_5bff.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-DEV-03"], users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM", "WIN-SOC\\SvcAcct"], riskScore: 7200, threatType: "LSASS Memory Access", mitre: "T1003.001", mitrePhase: "credential-access",   totalThreats: 95,  totalLogs: 38100 },
  { id: "ds-003", file: "windows_soc_data_3_838b.csv", date: "2026-03-26", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-03"], users: ["WIN-SOC\\Admin", "WIN-SOC\\Dev-01", "WIN-SOC\\Backup"], riskScore: 9100, threatType: "Lateral Movement via SMB", mitre: "T1021.002", mitrePhase: "lateral-movement",   totalThreats: 120, totalLogs: 52700 },
  { id: "ds-004", file: "windows_soc_data_4_068a.csv", date: "2026-03-29", computers: ["WIN-SOC-PROD-02", "WIN-SOC-DC-01"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\Admin", "NT AUTHORITY\\NETWORK SERVICE"], riskScore: 6800, threatType: "Scheduled Task Persistence", mitre: "T1053.005", mitrePhase: "persistence",  totalThreats: 140, totalLogs: 41300 },
  { id: "ds-005", file: "windows_soc_data_5_a006.csv", date: "2026-03-27", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-04"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User2", "NT AUTHORITY\\SYSTEM"], riskScore: 8100, threatType: "Registry Run Key Modification", mitre: "T1547.001", mitrePhase: "persistence",  totalThreats: 160, totalLogs: 63900 },
  { id: "ds-006", file: "windows_soc_data_6_4379.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-05"], users: ["WIN-SOC\\User1", "WIN-SOC\\SvcDB", "NT AUTHORITY\\SYSTEM"], riskScore: 5500, threatType: "Suspicious Network Exfiltration", mitre: "T1048", mitrePhase: "exfiltration",     totalThreats: 150, totalLogs: 29400 },
  { id: "ds-007", file: "windows_soc_data_7_8735.csv", date: "2026-03-26", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-01"], users: ["WIN-SOC\\Dev-01", "WIN-SOC\\Admin", "WIN-SOC\\Guest"], riskScore: 7600, threatType: "WMI Script Execution", mitre: "T1047", mitrePhase: "execution",               totalThreats: 180, totalLogs: 57800 },
  { id: "ds-008", file: "windows_soc_data_8_11c5.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-02", "WIN-SOC-DEV-02"], users: ["WIN-SOC\\Dev-01", "NT AUTHORITY\\SYSTEM", "WIN-SOC\\Analyst"], riskScore: 8900, threatType: "Pass-the-Hash Attack", mitre: "T1550.002", mitrePhase: "defense-evasion",   totalThreats: 155, totalLogs: 48600 },
  { id: "ds-009", file: "windows_soc_data_9_c913.csv", date: "2026-04-02", computers: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-01"], users: ["WIN-SOC\\Admin", "WIN-SOC\\User3", "NT AUTHORITY\\SYSTEM"], riskScore: 9400, threatType: "DCSync Active Directory Attack", mitre: "T1003.006", mitrePhase: "credential-access", totalThreats: 200, totalLogs: 71200 },
  { id: "ds-010", file: "windows_soc_data_10_7e32.csv", date: "2026-04-01", computers: ["WIN-SOC-PROD-01", "WIN-SOC-DC-01"], users: ["WIN-SOC\\User1", "WIN-SOC\\SvcMail", "NT AUTHORITY\\SYSTEM"], riskScore: 6200, threatType: "Token Impersonation / Privilege Escalation", mitre: "T1134.001", mitrePhase: "privilege-escalation", totalThreats: 240, totalLogs: 34500 },
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
    total_logs: meta.totalLogs,
    total_threats: meta.totalThreats,
    attack_chain_count: meta.computers.length,
    risk_score: meta.riskScore,
    threat_density: Math.round((meta.totalThreats / meta.totalLogs) * 10000) / 100,
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

// ─── USER004 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset4/user004logs.json
// Campaign: Multi-Stage Persistence & Exfiltration — 82% HIGH

function buildUser004Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-004",
    file_name: "user004logs.csv",
    total_logs: 10000,
    total_threats: 140,
    attack_chain_count: 7,
    risk_score: 8200,
    threat_density: 1.4,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u004-01", severity: "critical", title: "PowerShell Encoded IEX Download — Stage 1 Dropper", detection_type: "rule", rule_id: "SOC-T1059-001-004", mitre_techniques: ["PowerShell Encoded Command Execution"], mitre_ids: ["T1059.001"], affected_users: ["NT AUTHORITY\\SYSTEM", "WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "Multiple encoded PowerShell IEX Download Cradle executions across PROD-01 and PROD-02, consistent with an automated dropper delivering persistence payloads.", timestamp: "2026-03-29 23:56:00" },
    { id: "fnd-u004-02", severity: "critical", title: "LSASS Credential Dump + Pass-the-Hash", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-004", mitre_techniques: ["OS Credential Dumping: LSASS Memory", "Pass the Hash"], mitre_ids: ["T1003.001", "T1550.002"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"], count: 20, description: "ML model flagged mimikatz.exe accessing LSASS memory with 9.2-sigma deviation. NTLM hash extracted and reused for Pass-the-Hash lateral movement to PROD-03.", timestamp: "2026-03-29 23:58:00" },
    { id: "fnd-u004-03", severity: "high", title: "Malicious Scheduled Task + Registry Run Key Persistence", detection_type: "behavioral", rule_id: "SOC-T1053-T1547-004", mitre_techniques: ["Scheduled Task/Job", "Registry Run Keys / Startup Folder"], mitre_ids: ["T1053.005", "T1547.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-03"], count: 20, description: "Behavioral engine detected dual persistence: schtasks.exe created malicious task \\WindowsUpdate\\SvcHelper, and reg.exe wrote UpdateSvc to HKCU Run key — ensuring cross-reboot survival.", timestamp: "2026-03-29 23:56:02" },
    { id: "fnd-u004-04", severity: "high", title: "AV/EDR Disabled + AMSI Bypass", detection_type: "rule", rule_id: "SOC-T1562-001-004", mitre_techniques: ["Impair Defenses: Disable or Modify Tools"], mitre_ids: ["T1562.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], count: 15, description: "sc.exe disabled Windows Defender and AMSI was bypassed via registry modification — blinding host-based security tools before payload execution.", timestamp: "2026-03-30 00:10:00" },
    { id: "fnd-u004-05", severity: "high", title: "Exfiltration Over C2 Channel", detection_type: "rule", rule_id: "SOC-T1041-004", mitre_techniques: ["Exfiltration Over C2 Channel"], mitre_ids: ["T1041"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-05"], count: 15, description: "PowerShell exfiltrated a 7-Zip archive over HTTPS C2 to 185.220.101.88:443 — data staging and bulk transfer confirmed at 90 MB/s.", timestamp: "2026-03-30 00:45:00" },
    { id: "fnd-u004-06", severity: "high", title: "Non-Standard Port C2 Beacon", detection_type: "ml_anomaly", rule_id: "SOC-T1571-004", mitre_techniques: ["Non-Standard Port C2"], mitre_ids: ["T1571"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-06"], count: 10, description: "ML model detected repeated outbound connections on port 4444 to a known C2 IP — non-standard port bypassing standard firewall rules.", timestamp: "2026-03-30 00:30:00" },
    { id: "fnd-u004-07", severity: "medium", title: "Remote System Discovery Sweep", detection_type: "heuristic", rule_id: "SOC-T1018-004", mitre_techniques: ["Remote System Discovery"], mitre_ids: ["T1018"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01"], count: 15, description: "Sequential net view, arp -a, and nmap-style enumeration detected — classic post-exploitation discovery sweep within 60 seconds.", timestamp: "2026-03-30 00:05:00" },
    { id: "fnd-u004-08", severity: "medium", title: "Keylogger Activity + Data Collection", detection_type: "yara_match", rule_id: "SOC-T1056-001-004", mitre_techniques: ["Keylogging", "Archive Collected Data"], mitre_ids: ["T1056.001", "T1560.001"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-07"], count: 10, description: "YARA rule KEYLOGGER_RAW_v2 matched a process capturing keystrokes and writing to an encrypted log file before archiving for exfiltration.", timestamp: "2026-03-30 00:20:00" },
    { id: "fnd-u004-09", severity: "medium", title: "Local Account Brute Force Attempt", detection_type: "rule", rule_id: "SOC-T1078-003-004", mitre_techniques: ["Valid Accounts: Local Accounts"], mitre_ids: ["T1078.003"], affected_users: ["WIN-SOC\\User4", "WIN-SOC\\SvcAcct"], affected_hosts: ["WIN-SOC-PROD-08"], count: 15, description: "342 failed local account logon attempts within 5 minutes, followed by successful authentication — brute force leading to initial access via local account.", timestamp: "2026-03-29 23:50:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-004-01", chain_index: 1, title: "PowerShell Dropper → Scheduled Task + Registry Persistence", computer: "WIN-SOC-PROD-01", chain_confidence: 0.94, kill_chain_phases: ["execution", "persistence"], affected_users: ["NT AUTHORITY\\SYSTEM", "WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-004-log-1", "fnd-ds-004-log-2", "fnd-ds-004-log-3"] },
    { chain_id: "chain-ds-004-02", chain_index: 2, title: "LSASS Credential Dump + Pass-the-Hash Lateral Movement", computer: "WIN-SOC-PROD-02", chain_confidence: 0.97, kill_chain_phases: ["credential-access", "lateral-movement"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"], events: ["fnd-ds-004-log-4", "fnd-ds-004-log-5"] },
    { chain_id: "chain-ds-004-03", chain_index: 3, title: "AV/EDR Disabled → Payload Execution", computer: "WIN-SOC-PROD-04", chain_confidence: 0.91, kill_chain_phases: ["defense-evasion", "execution"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], events: ["fnd-ds-004-log-6"] },
    { chain_id: "chain-ds-004-04", chain_index: 4, title: "Non-Standard Port C2 Beaconing", computer: "WIN-SOC-PROD-06", chain_confidence: 0.89, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-06"], events: ["fnd-ds-004-log-7"] },
    { chain_id: "chain-ds-004-05", chain_index: 5, title: "Post-Exploitation Discovery Sweep", computer: "WIN-SOC-PROD-01", chain_confidence: 0.88, kill_chain_phases: ["discovery"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01"], events: ["fnd-ds-004-log-8"] },
    { chain_id: "chain-ds-004-06", chain_index: 6, title: "Keylogger Installation + Data Staging", computer: "WIN-SOC-PROD-07", chain_confidence: 0.92, kill_chain_phases: ["collection"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-07"], events: ["fnd-ds-004-log-9"] },
    { chain_id: "chain-ds-004-07", chain_index: 7, title: "C2 Exfiltration over HTTPS", computer: "WIN-SOC-PROD-05", chain_confidence: 0.95, kill_chain_phases: ["exfiltration"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-05"], events: ["fnd-ds-004-log-10"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user004logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🟠 HIGH (82%) |
| Total Logs | 10,000 |
| Threat Events | 140 |
| Attack Chains | 7 |
| Affected Hosts | 8 |
| Affected Users | 10 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **multi-stage high-severity threat campaign** was detected in **user004logs.csv** spanning **7 distinct attack chains** across 10 MITRE ATT&CK tactic categories.

Primary attack vectors: PowerShell Encoded Execution, LSASS Credential Dumping, Dual Persistence (Scheduled Task + Registry Run Keys), AV/EDR Disablement, AMSI Bypass, Non-Standard Port C2 Beaconing, Keylogging, and HTTPS C2 Exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-08**

Immediate containment and forensic investigation is required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-03-29 23:50:00 | WIN-SOC-PROD-08 | Local Account Brute Force — Initial Access |
| 2026-03-29 23:56:00 | WIN-SOC-PROD-01 | Encoded IEX Download — Stage 1 Dropper |
| 2026-03-29 23:56:02 | WIN-SOC-PROD-01 | Scheduled Task + Registry Run Key Created |
| 2026-03-29 23:58:00 | WIN-SOC-PROD-02 | LSASS Memory Dump (Mimikatz) |
| 2026-03-30 00:05:00 | WIN-SOC-PROD-01 | Remote System Discovery Sweep |
| 2026-03-30 00:10:00 | WIN-SOC-PROD-04 | AV/EDR Disabled + AMSI Bypass |
| 2026-03-30 00:20:00 | WIN-SOC-PROD-07 | Keylogger Installed + Data Collection |
| 2026-03-30 00:30:00 | WIN-SOC-PROD-06 | Non-Standard Port C2 Beacon (Port 4444) |
| 2026-03-30 00:45:00 | WIN-SOC-PROD-05 | HTTPS C2 Exfiltration to 185.220.101.88 |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** PowerShell IEX Dropper → Scheduled Task + Registry Run Key Persistence
- **Chain 2:** LSASS Credential Dump (Mimikatz) → Pass-the-Hash → Lateral Movement
- **Chain 3:** AV/EDR Disabled → AMSI Bypass → Payload Execution
- **Chain 4:** Non-Standard Port 4444 C2 Beaconing
- **Chain 5:** Post-Exploitation Discovery Sweep (net view, arp, nmap)
- **Chain 6:** Keylogger Deployment → Data Staging + Archive Creation
- **Chain 7:** HTTPS C2 Exfiltration → Data Transfer to 185.220.101.88:443

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1078.003 | Valid Accounts: Local Accounts | Initial Access |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1053.005 | Scheduled Task | Persistence |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1562.001 | Disable or Modify Tools (AV/EDR + AMSI) | Defense Evasion |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1550.002 | Pass the Hash | Lateral Movement |
| T1018 | Remote System Discovery | Discovery |
| T1571 | Non-Standard Port C2 | Command & Control |
| T1056.001 | Keylogging | Collection |
| T1560.001 | Archive Collected Data | Collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | LSASS Credential Dump + Pass-the-Hash | 20 |
| 🟠 HIGH | Exfiltration Over C2 Channel (HTTPS) | 15 |
| 🟠 HIGH | Scheduled Task + Registry Persistence | 20 |
| 🟠 HIGH | PowerShell Encoded Execution | 20 |
| 🟠 HIGH | AV/EDR Disabled + AMSI Bypass | 15 |
| 🟡 MEDIUM | Remote System Discovery Sweep | 15 |
| 🟡 MEDIUM | Keylogger Activity + Collection | 10 |
| 🟡 MEDIUM | Non-Standard Port C2 (Port 4444) | 10 |
| 🟡 MEDIUM | Local Account Brute Force | 15 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — PowerShell dropper, scheduled task, registry persistence, discovery
- WIN-SOC-PROD-02 — LSASS dump, Pass-the-Hash origin
- WIN-SOC-PROD-03 — Pass-the-Hash lateral movement target
- WIN-SOC-PROD-04 — AV/EDR disabled, AMSI bypass
- WIN-SOC-PROD-05 — C2 exfiltration origin
- WIN-SOC-PROD-06 — Non-standard port C2 beacon
- WIN-SOC-PROD-07 — Keylogger deployment, data staging
- WIN-SOC-PROD-08 — Initial access via brute force

**Users**
- NT AUTHORITY\\SYSTEM
- WIN-SOC\\Dev-01
- WIN-SOC\\User2
- WIN-SOC\\User3
- WIN-SOC\\User4
- WIN-SOC\\SvcAcct

---

## 🛡️ 8. RECOMMENDATIONS
- **Enforce MFA** and account lockout policies to prevent brute force initial access
- **Enable Credential Guard** to protect LSASS from memory access tools
- **Monitor and alert** on schtasks.exe and reg.exe execution from non-admin processes
- **Block outbound port 4444** and monitor non-standard C2 communication patterns
- **Deploy AMSI bypass detection** rules in EDR and PowerShell logging (Event ID 4104)
- **Alert on AV service stop events** (sc.exe targeting WinDefend or similar)
- **Monitor large outbound HTTPS transfers** and archive creation in temp directories
- **Isolate all 8 affected hosts** and rotate credentials for all 10 affected accounts

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 82% (HIGH)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | HIGH |
| Confidence | 95% |
`

  const summary: MockSummary = {
    scan_id: "user-004",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A HIGH-severity multi-stage threat campaign was detected in user004logs.csv. Analysis identified 140 threat events across 8 hosts and 7 attack chains. Primary vectors: LSASS Credential Dumping, PowerShell Encoded Execution, Dual Persistence (Scheduled Task + Registry), AV/EDR Disablement, Non-Standard Port C2, Keylogging, and HTTPS Exfiltration. Risk Score: 82% HIGH.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A HIGH-severity multi-stage threat campaign was detected in user004logs.csv spanning 7 attack chains. Techniques: LSASS Dump (T1003.001), Pass-the-Hash (T1550.002), PowerShell Execution (T1059.001), Scheduled Task (T1053.005), Registry Persistence (T1547.001), AV Disable (T1562.001), Non-Standard Port C2 (T1571), Keylogging (T1056.001), and HTTPS Exfiltration (T1041). Risk Score: 82% HIGH.",
      attack_narrative: "Between 2026-03-29 23:50 UTC and 2026-03-30 00:45 UTC, a threat actor executed a 7-chain campaign. Initial access was via local account brute force. PowerShell droppers established dual persistence via scheduled tasks and registry run keys. Mimikatz dumped LSASS credentials enabling Pass-the-Hash lateral movement. AV/EDR was disabled and AMSI bypassed before further payload execution. A keylogger was deployed for data collection while C2 beaconing occurred over non-standard port 4444. Finally, staged data was exfiltrated over HTTPS to 185.220.101.88.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-08\n\n**Users:** NT AUTHORITY\\SYSTEM, WIN-SOC\\Dev-01, WIN-SOC\\User2, WIN-SOC\\User3, WIN-SOC\\User4, WIN-SOC\\SvcAcct",
      remediation_steps: "1. **Enforce MFA** and account lockout for all local accounts.\n2. **Enable Credential Guard** to block LSASS memory access.\n3. **Remove** unauthorized scheduled tasks and registry Run keys across all hosts.\n4. **Block outbound port 4444** and alert on non-standard C2 patterns.\n5. **Reset credentials** for all 6 affected accounts.\n6. **Deploy AMSI protection** and Script Block Logging (Event ID 4104).\n7. **Isolate all 8 affected hosts** immediately.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER005 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset5/user005logs.json
// Campaign: Multi-Stage Persistent Intrusion — 74% MEDIUM-HIGH

function buildUser005Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-005",
    file_name: "user005logs.csv",
    total_logs: 10000,
    total_threats: 160,
    attack_chain_count: 8,
    risk_score: 7400,
    threat_density: 1.6,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u005-01", severity: "critical", title: "LSASS Memory Dump — Full Credential Harvest", detection_type: "ml_anomaly", rule_id: "SOC-T1003-001-005", mitre_techniques: ["OS Credential Dumping: LSASS Memory"], mitre_ids: ["T1003.001"], affected_users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 15, description: "ML model flagged LSASS memory access with 9.0-sigma deviation from baseline. Full credential material extracted including NTLM hashes and Kerberos tickets.", timestamp: "2026-03-27 23:41:45" },
    { id: "fnd-u005-02", severity: "critical", title: "Kerberoasting Attack — SPN Ticket Harvesting", detection_type: "heuristic", rule_id: "SOC-T1558-003-005", mitre_techniques: ["Kerberoasting"], mitre_ids: ["T1558.003"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-DC-01"], count: 10, description: "Heuristic engine detected 1,400+ Kerberos TGS requests for service accounts in under 60 seconds — classic Kerberoasting pattern targeting service principal names for offline hash cracking.", timestamp: "2026-03-28 00:10:00" },
    { id: "fnd-u005-03", severity: "high", title: "Registry Run Key Modification for Persistence", detection_type: "rule", rule_id: "SOC-T1547-001-005", mitre_techniques: ["Registry Run Keys / Startup Folder"], mitre_ids: ["T1547.001"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-03"], count: 20, description: "reg.exe modified HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run with a malicious payload entry — ensuring automatic execution on every system boot.", timestamp: "2026-03-27 23:42:00" },
    { id: "fnd-u005-04", severity: "high", title: "Process Hollowing + Token Impersonation — Privilege Escalation", detection_type: "behavioral", rule_id: "SOC-T1055-002-005", mitre_techniques: ["Process Hollowing", "Token Impersonation/Theft"], mitre_ids: ["T1055.002", "T1134.001"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-04"], count: 15, description: "Behavioral engine detected process hollowing: a legitimate svchost.exe was suspended and its memory replaced with malicious code. Token impersonation then elevated to SYSTEM.", timestamp: "2026-03-28 00:05:00" },
    { id: "fnd-u005-05", severity: "high", title: "RDP Lateral Movement — Remote Desktop Access", detection_type: "rule", rule_id: "SOC-T1021-001-005", mitre_techniques: ["Remote Desktop Protocol"], mitre_ids: ["T1021.001"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-05", "WIN-SOC-PROD-06"], count: 15, description: "Successful RDP connections established from PROD-04 to PROD-05 and PROD-06 outside business hours using credentials obtained from LSASS dump.", timestamp: "2026-03-28 00:15:00" },
    { id: "fnd-u005-06", severity: "high", title: "Active Vulnerability Scanning — Reconnaissance", detection_type: "heuristic", rule_id: "SOC-T1595-002-005", mitre_techniques: ["Active Scanning: Vulnerability Scanning"], mitre_ids: ["T1595.002"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01"], count: 20, description: "Heuristic engine detected mass port scanning and service enumeration across the internal subnet — consistent with automated vulnerability scanner pre-exploitation behavior.", timestamp: "2026-03-27 23:30:00" },
    { id: "fnd-u005-07", severity: "medium", title: "Scheduled Task Persistence — Backup Mechanism", detection_type: "rule", rule_id: "SOC-T1053-005-005", mitre_techniques: ["Scheduled Task/Job"], mitre_ids: ["T1053.005"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-07"], count: 15, description: "Scheduled task created to execute malicious payload every 30 minutes as a persistence backup mechanism alongside the registry run key.", timestamp: "2026-03-28 00:20:00" },
    { id: "fnd-u005-08", severity: "medium", title: "Registry Modification — AMSI + Script Block Logging Disabled", detection_type: "behavioral", rule_id: "SOC-T1112-005", mitre_techniques: ["Modify Registry"], mitre_ids: ["T1112"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], count: 15, description: "Registry modifications detected disabling AMSI and Script Block Logging — classic defense evasion before PowerShell-based payload execution.", timestamp: "2026-03-28 00:02:00" },
    { id: "fnd-u005-09", severity: "medium", title: "Screen Capture + DNS-Based Exfiltration", detection_type: "ml_anomaly", rule_id: "SOC-T1113-005", mitre_techniques: ["Screen Capture", "Exfiltration Over Alternative Protocol"], mitre_ids: ["T1113", "T1048"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-08"], count: 25, description: "ML model detected periodic screenshot capture (every 5 minutes) and DNS TXT query-based exfiltration — Shannon entropy analysis confirmed encoded data in subdomain queries.", timestamp: "2026-03-28 01:00:00" },
    { id: "fnd-u005-10", severity: "medium", title: "Remote Access Software — Covert RAT Installed", detection_type: "yara_match", rule_id: "SOC-T1219-005", mitre_techniques: ["Remote Access Software"], mitre_ids: ["T1219"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-09"], count: 10, description: "YARA rule RAT_COVERT_v4 matched a commercial remote access tool installed as a service — providing persistent covert access to the adversary outside normal C2 channels.", timestamp: "2026-03-28 00:30:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-005-01", chain_index: 1, title: "Vulnerability Scanning → PowerShell Dropper → LSASS Dump", computer: "WIN-SOC-PROD-01", chain_confidence: 0.93, kill_chain_phases: ["reconnaissance", "execution", "credential-access"], affected_users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-005-log-1", "fnd-ds-005-log-2"] },
    { chain_id: "chain-ds-005-02", chain_index: 2, title: "Registry Run Key + Scheduled Task Persistence", computer: "WIN-SOC-PROD-01", chain_confidence: 0.91, kill_chain_phases: ["persistence"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-03"], events: ["fnd-ds-005-log-3"] },
    { chain_id: "chain-ds-005-03", chain_index: 3, title: "AMSI Bypass + Registry Defense Evasion", computer: "WIN-SOC-PROD-02", chain_confidence: 0.89, kill_chain_phases: ["defense-evasion"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], events: ["fnd-ds-005-log-4"] },
    { chain_id: "chain-ds-005-04", chain_index: 4, title: "Process Hollowing + Token Impersonation → Privilege Escalation", computer: "WIN-SOC-PROD-04", chain_confidence: 0.95, kill_chain_phases: ["privilege-escalation"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-04"], events: ["fnd-ds-005-log-5"] },
    { chain_id: "chain-ds-005-05", chain_index: 5, title: "RDP Lateral Movement to PROD-05 and PROD-06", computer: "WIN-SOC-PROD-05", chain_confidence: 0.90, kill_chain_phases: ["lateral-movement"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-05", "WIN-SOC-PROD-06"], events: ["fnd-ds-005-log-6"] },
    { chain_id: "chain-ds-005-06", chain_index: 6, title: "Kerberoasting — Domain Service Ticket Harvesting", computer: "WIN-SOC-DC-01", chain_confidence: 0.96, kill_chain_phases: ["credential-access"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-DC-01"], events: ["fnd-ds-005-log-7"] },
    { chain_id: "chain-ds-005-07", chain_index: 7, title: "Screen Capture → DNS Exfiltration", computer: "WIN-SOC-PROD-08", chain_confidence: 0.88, kill_chain_phases: ["collection", "exfiltration"], affected_users: ["WIN-SOC\\User2"], affected_hosts: ["WIN-SOC-PROD-08"], events: ["fnd-ds-005-log-8"] },
    { chain_id: "chain-ds-005-08", chain_index: 8, title: "Covert RAT Installed for Persistent Access", computer: "WIN-SOC-PROD-09", chain_confidence: 0.87, kill_chain_phases: ["command-and-control", "persistence"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-09"], events: ["fnd-ds-005-log-9"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user005logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🟡 MEDIUM-HIGH (74%) |
| Total Logs | 10,000 |
| Threat Events | 160 |
| Attack Chains | 8 |
| Affected Hosts | 9 |
| Affected Users | 11 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **sustained multi-stage threat campaign** was detected in **user005logs.csv** spanning **8 distinct attack chains** across 12 MITRE ATT&CK tactic categories.

The adversary demonstrated deliberate, low-and-slow TTPs: active vulnerability scanning, process hollowing, Kerberoasting, RDP lateral movement, and DNS-based exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-09** and **WIN-SOC-DC-01**

Immediate investigation and remediation is required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-03-27 23:30:00 | WIN-SOC-PROD-01 | Vulnerability Scanning — Reconnaissance |
| 2026-03-27 23:41:45 | WIN-SOC-PROD-01 | PowerShell Encoded IEX Download |
| 2026-03-27 23:42:00 | WIN-SOC-PROD-01 | Registry Run Key Persistence Written |
| 2026-03-28 00:02:00 | WIN-SOC-PROD-02 | AMSI + Script Block Logging Disabled |
| 2026-03-28 00:05:00 | WIN-SOC-PROD-04 | Process Hollowing + Token Impersonation |
| 2026-03-28 00:10:00 | WIN-SOC-DC-01 | Kerberoasting — 1,400+ SPN Requests |
| 2026-03-28 00:15:00 | WIN-SOC-PROD-05 | RDP Lateral Movement Initiated |
| 2026-03-28 00:20:00 | WIN-SOC-PROD-07 | Scheduled Task Persistence Created |
| 2026-03-28 00:30:00 | WIN-SOC-PROD-09 | Covert RAT Installed as Service |
| 2026-03-28 01:00:00 | WIN-SOC-PROD-08 | Screen Capture + DNS Exfiltration |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** Vulnerability Scanning → PowerShell Dropper → LSASS Credential Dump
- **Chain 2:** Registry Run Key + Scheduled Task Dual Persistence
- **Chain 3:** AMSI Bypass + Registry Defense Evasion
- **Chain 4:** Process Hollowing → Token Impersonation → SYSTEM Escalation
- **Chain 5:** RDP Lateral Movement to PROD-05 and PROD-06
- **Chain 6:** Kerberoasting — Domain Service Ticket Harvesting (1,400+ SPNs)
- **Chain 7:** Screen Capture Collection → DNS-Based Exfiltration
- **Chain 8:** Covert RAT Service Installation for Persistent Access

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence |
| T1053.005 | Scheduled Task | Persistence |
| T1219 | Remote Access Software (RAT) | Persistence |
| T1055.002 | Process Hollowing | Privilege Escalation |
| T1134.001 | Token Impersonation/Theft | Privilege Escalation |
| T1112 | Modify Registry (AMSI/Logging Disable) | Defense Evasion |
| T1003.001 | LSASS Memory Dump | Credential Access |
| T1558.003 | Kerberoasting | Credential Access |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1113 | Screen Capture | Collection |
| T1048 | Exfiltration Over Alternative Protocol (DNS) | Exfiltration |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | LSASS Credential Dump | 15 |
| 🔴 CRITICAL | Kerberoasting Attack | 10 |
| 🟠 HIGH | Registry Run Key Persistence | 20 |
| 🟠 HIGH | Process Hollowing + Token Impersonation | 15 |
| 🟠 HIGH | RDP Lateral Movement | 15 |
| 🟠 HIGH | Active Vulnerability Scanning | 20 |
| 🟡 MEDIUM | Scheduled Task Persistence | 15 |
| 🟡 MEDIUM | AMSI + Registry Defense Evasion | 15 |
| 🟡 MEDIUM | Screen Capture + DNS Exfiltration | 25 |
| 🟡 MEDIUM | Covert RAT Installed | 10 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — Reconnaissance, dropper, LSASS dump, registry persistence
- WIN-SOC-PROD-02 — AMSI bypass, defense evasion
- WIN-SOC-PROD-03 — Registry persistence target
- WIN-SOC-PROD-04 — Process hollowing, token impersonation
- WIN-SOC-PROD-05 — RDP lateral movement target
- WIN-SOC-PROD-06 — RDP lateral movement target
- WIN-SOC-PROD-07 — Scheduled task persistence
- WIN-SOC-PROD-08 — Screen capture, DNS exfiltration
- WIN-SOC-PROD-09 — Covert RAT installation
- WIN-SOC-DC-01 — Kerberoasting target

**Users**
- WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\User3
- WIN-SOC\\Admin, NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Enable Credential Guard** to prevent LSASS memory access and Kerberos ticket harvesting
- **Implement Kerberoasting defenses** — use MSA/gMSA for service accounts, enforce AES-only encryption
- **Block RDP from non-admin hosts** via network segmentation and conditional access
- **Monitor and alert on AMSI bypass** registry modifications (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell)
- **Deploy process injection detection** rules (Sysmon Event ID 8: CreateRemoteThread)
- **Block DNS-based exfiltration** — limit DNS TXT query length and monitor high-entropy subdomains
- **Alert on RAT service installation** via EDR behavioral rules
- **Isolate all 9 affected hosts** and rotate credentials for all 11 affected accounts

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 74% (MEDIUM-HIGH)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | MEDIUM |
| Severity | MEDIUM-HIGH |
| Confidence | 93% |
`

  const summary: MockSummary = {
    scan_id: "user-005",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A MEDIUM-HIGH severity multi-stage persistent intrusion was detected in user005logs.csv. Analysis identified 160 threat events across 9 hosts and 8 attack chains. Primary vectors: LSASS Dump, Kerberoasting, Process Hollowing, RDP Lateral Movement, DNS Exfiltration, and Covert RAT Persistence. Risk Score: 74% MEDIUM-HIGH.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A MEDIUM-HIGH severity persistent intrusion was detected in user005logs.csv spanning 8 attack chains. Techniques: LSASS Dump (T1003.001), Kerberoasting (T1558.003), Process Hollowing (T1055.002), Token Impersonation (T1134.001), Registry Persistence (T1547.001), RDP Lateral Movement (T1021.001), Screen Capture (T1113), DNS Exfiltration (T1048). Risk Score: 74% MEDIUM-HIGH.",
      attack_narrative: "Between 2026-03-27 23:30 UTC and 2026-03-28 01:00 UTC, a deliberate low-and-slow threat actor executed an 8-chain campaign. Reconnaissance via vulnerability scanning preceded PowerShell dropper execution. LSASS was dumped for credential harvesting. Registry and scheduled task persistence ensured survival across reboots. Process hollowing and token impersonation escalated to SYSTEM. RDP lateral movement spread across 2 additional hosts. Kerberoasting harvested 1,400+ SPN tickets for offline cracking. Screen capture collection was exfiltrated via DNS tunneling. A covert RAT was installed for long-term persistent access.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-09, WIN-SOC-DC-01\n\n**Users:** WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\User3, WIN-SOC\\Admin, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Enable Credential Guard** to block LSASS access and Kerberoasting.\n2. **Convert service accounts** to MSA/gMSA with AES-only Kerberos encryption.\n3. **Block RDP** from non-admin hosts via network segmentation.\n4. **Monitor AMSI bypass** registry modifications and enable Script Block Logging.\n5. **Deploy Sysmon** process injection detection (Event ID 8).\n6. **Block DNS exfiltration** by filtering long TXT record subdomains.\n7. **Remove the covert RAT** service and scan for similar installations.\n8. **Rotate credentials** for all 11 affected accounts.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER006 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset6/user006logs.json
// Campaign: Advanced Persistent Intrusion with Golden Ticket & Multi-Protocol Exfil — 91% CRITICAL

function buildUser006Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-006",
    file_name: "user006logs.csv",
    total_logs: 10000,
    total_threats: 150,
    attack_chain_count: 7,
    risk_score: 9100,
    threat_density: 1.5,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u006-01", severity: "critical", title: "Golden Ticket Attack — krbtgt Kerberos Forgery", detection_type: "ml_anomaly", rule_id: "SOC-T1558-001-006", mitre_techniques: ["Steal or Forge Kerberos Tickets: Golden Ticket"], mitre_ids: ["T1558.001"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], count: 10, description: "ML model detected forged Kerberos TGT with anomalous lifetime (10 years) originating from a non-DC endpoint — Golden Ticket forgery confirmed. All domain credentials must be considered compromised.", timestamp: "2026-04-02 00:30:00" },
    { id: "fnd-u006-02", severity: "critical", title: "NTDS.dit Credential Dump — Full Domain Credential Harvest", detection_type: "rule", rule_id: "SOC-T1003-003-006", mitre_techniques: ["OS Credential Dumping: NTDS"], mitre_ids: ["T1003.003"], affected_users: ["WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], count: 10, description: "ntdsutil.exe and vssadmin used to extract the NTDS.dit database from WIN-SOC-DC-01 — exposing all domain account credentials including krbtgt and all user NTLM hashes.", timestamp: "2026-04-02 00:35:00" },
    { id: "fnd-u006-03", severity: "critical", title: "Multi-Protocol Data Exfiltration (C2 + OneDrive)", detection_type: "behavioral", rule_id: "SOC-T1048-006", mitre_techniques: ["Data Exfiltration via C2", "Exfiltration to Cloud Storage"], mitre_ids: ["T1048", "T1567.002"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 20, description: "Behavioral analysis detected parallel exfiltration: data sent over encrypted C2 channel and simultaneously uploaded to an attacker-controlled OneDrive tenant — 2-channel exfiltration to maximize throughput.", timestamp: "2026-04-02 01:00:00" },
    { id: "fnd-u006-04", severity: "high", title: "Supply Chain Compromise — Trojanized Software Package", detection_type: "yara_match", rule_id: "SOC-T1195-002-006", mitre_techniques: ["Compromise Software Supply Chain"], mitre_ids: ["T1195.002"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01"], count: 15, description: "YARA rule TROJAN_PKG_v3 matched a software update package containing an embedded malicious DLL — supply chain compromise identified as the initial access vector.", timestamp: "2026-04-02 00:18:03" },
    { id: "fnd-u006-05", severity: "high", title: "WMI Event Subscription Persistence (Fileless)", detection_type: "rule", rule_id: "SOC-T1546-003-006", mitre_techniques: ["WMI Event Subscription Persistence"], mitre_ids: ["T1546.003"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-02"], count: 15, description: "wmiprvse.exe created a permanent WMI event subscription that triggers payload execution on every system startup — a fileless persistence technique surviving disk forensics.", timestamp: "2026-04-02 00:20:00" },
    { id: "fnd-u006-06", severity: "high", title: "Group Policy Modification — Domain-Wide Malicious GPO", detection_type: "behavioral", rule_id: "SOC-T1484-001-006", mitre_techniques: ["Group Policy Modification"], mitre_ids: ["T1484.001"], affected_users: ["WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], count: 10, description: "Behavioral engine detected unauthorized GPO creation deploying a malicious login script to all domain computers — enabling mass lateral deployment with a single policy change.", timestamp: "2026-04-02 00:40:00" },
    { id: "fnd-u006-07", severity: "high", title: "Protocol Tunneling C2 — HTTPS over DNS Covert Channel", detection_type: "ml_anomaly", rule_id: "SOC-T1572-006", mitre_techniques: ["Protocol Tunneling C2"], mitre_ids: ["T1572"], affected_users: ["WIN-SOC\\SvcMail"], affected_hosts: ["WIN-SOC-PROD-03"], count: 20, description: "ML model detected HTTPS traffic tunneled over DNS (DoH covert channel) to a rented server in a bulletproof hosting ASN — encrypted C2 evading perimeter inspection.", timestamp: "2026-04-02 00:45:00" },
    { id: "fnd-u006-08", severity: "medium", title: "Rundll32 LOLBin Proxy Execution — Defense Evasion", detection_type: "heuristic", rule_id: "SOC-T1218-011-006", mitre_techniques: ["Signed Binary Proxy Execution: Rundll32"], mitre_ids: ["T1218.011"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-04"], count: 15, description: "Heuristic engine flagged rundll32.exe executing a malicious DLL from a non-standard path — living-off-the-land technique to bypass application whitelisting.", timestamp: "2026-04-02 00:22:00" },
    { id: "fnd-u006-09", severity: "medium", title: "Domain Account Discovery — LDAP Enumeration", detection_type: "rule", rule_id: "SOC-T1087-002-006", mitre_techniques: ["Account Discovery: Domain Account"], mitre_ids: ["T1087.002"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-05"], count: 15, description: "LDAP enumeration detected: 3,200+ queries for domain accounts, group memberships, and computer objects within 2 minutes — automated AD recon tool (BloodHound) behavioral signature.", timestamp: "2026-04-02 00:25:00" },
    { id: "fnd-u006-10", severity: "medium", title: "Cloud Storage Data Exfiltration — SharePoint/OneDrive", detection_type: "ml_anomaly", rule_id: "SOC-T1530-006", mitre_techniques: ["Data from Cloud Storage Object"], mitre_ids: ["T1530"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 10, description: "ML model detected mass OAuth token-based access to SharePoint/OneDrive from an anomalous device fingerprint — attacker leveraged a refresh token to exfiltrate cloud-stored sensitive documents.", timestamp: "2026-04-02 01:05:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-006-01", chain_index: 1, title: "Supply Chain Compromise → Encoded PowerShell Dropper", computer: "WIN-SOC-PROD-01", chain_confidence: 0.94, kill_chain_phases: ["initial-access", "execution"], affected_users: ["NT AUTHORITY\\SYSTEM", "WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-006-log-1", "fnd-ds-006-log-2"] },
    { chain_id: "chain-ds-006-02", chain_index: 2, title: "WMI Event Subscription Fileless Persistence", computer: "WIN-SOC-PROD-02", chain_confidence: 0.92, kill_chain_phases: ["persistence"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-02"], events: ["fnd-ds-006-log-3"] },
    { chain_id: "chain-ds-006-03", chain_index: 3, title: "Rundll32 LOLBin → Domain Account LDAP Enumeration", computer: "WIN-SOC-PROD-04", chain_confidence: 0.90, kill_chain_phases: ["defense-evasion", "discovery"], affected_users: ["WIN-SOC\\Dev-01", "WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-04", "WIN-SOC-PROD-05"], events: ["fnd-ds-006-log-4"] },
    { chain_id: "chain-ds-006-04", chain_index: 4, title: "Golden Ticket Forgery → NTDS.dit Dump → GPO Modification", computer: "WIN-SOC-DC-01", chain_confidence: 0.99, kill_chain_phases: ["credential-access", "privilege-escalation"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], events: ["fnd-ds-006-log-5", "fnd-ds-006-log-6"] },
    { chain_id: "chain-ds-006-05", chain_index: 5, title: "Protocol Tunneling C2 (HTTPS-over-DNS)", computer: "WIN-SOC-PROD-03", chain_confidence: 0.91, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\SvcMail"], affected_hosts: ["WIN-SOC-PROD-03"], events: ["fnd-ds-006-log-7"] },
    { chain_id: "chain-ds-006-06", chain_index: 6, title: "Cloud Storage + C2 Dual-Channel Exfiltration", computer: "WIN-SOC-FILESVR-01", chain_confidence: 0.97, kill_chain_phases: ["collection", "exfiltration"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-FILESVR-01"], events: ["fnd-ds-006-log-8"] },
    { chain_id: "chain-ds-006-07", chain_index: 7, title: "OAuth Token Abuse → SharePoint/OneDrive Data Theft", computer: "WIN-SOC-FILESVR-01", chain_confidence: 0.93, kill_chain_phases: ["collection", "exfiltration"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-FILESVR-01"], events: ["fnd-ds-006-log-9"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user006logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🔴 CRITICAL (91%) |
| Total Logs | 10,000 |
| Threat Events | 150 |
| Attack Chains | 7 |
| Affected Hosts | 8 |
| Affected Users | 10 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **critical advanced persistent intrusion** was detected in **user006logs.csv** spanning **7 distinct attack chains** across 11 MITRE ATT&CK tactic categories.

The adversary demonstrated nation-state-level capabilities: supply chain compromise as initial access, Golden Ticket Kerberos forgery, full NTDS.dit domain credential harvest, GPO-based mass lateral deployment, and dual-channel exfiltration (C2 + OneDrive).

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-05**, **WIN-SOC-DC-01**, **WIN-SOC-FILESVR-01**

Immediate containment, credential rotation including krbtgt (×2), and forensic investigation are required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-02 00:18:03 | WIN-SOC-PROD-01 | Supply Chain Trojanized Package — Initial Access |
| 2026-04-02 00:20:00 | WIN-SOC-PROD-02 | WMI Event Subscription Persistence Created |
| 2026-04-02 00:22:00 | WIN-SOC-PROD-04 | Rundll32 LOLBin Proxy Execution |
| 2026-04-02 00:25:00 | WIN-SOC-PROD-05 | LDAP Domain Account Enumeration (BloodHound) |
| 2026-04-02 00:30:00 | WIN-SOC-DC-01 | Golden Ticket Forgery — krbtgt Hash Abused |
| 2026-04-02 00:35:00 | WIN-SOC-DC-01 | NTDS.dit Database Extracted via vssadmin |
| 2026-04-02 00:40:00 | WIN-SOC-DC-01 | Malicious GPO Deployed Domain-Wide |
| 2026-04-02 00:45:00 | WIN-SOC-PROD-03 | Protocol Tunneling C2 (HTTPS-over-DNS) |
| 2026-04-02 01:00:00 | WIN-SOC-FILESVR-01 | Dual-Channel Exfiltration (C2 + OneDrive) |
| 2026-04-02 01:05:00 | WIN-SOC-FILESVR-01 | OAuth Token Abuse — SharePoint Data Theft |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** Supply Chain Compromise → PowerShell Encoded Dropper
- **Chain 2:** WMI Event Subscription — Fileless Persistence (Survives Reboots)
- **Chain 3:** Rundll32 LOLBin Proxy → LDAP Domain Account Enumeration (BloodHound)
- **Chain 4:** Golden Ticket Forgery → NTDS.dit Full Domain Credential Dump → Malicious GPO
- **Chain 5:** Protocol Tunneling C2 — HTTPS-over-DNS Covert Channel
- **Chain 6:** Dual-Channel Exfiltration — Encrypted C2 + OneDrive Upload
- **Chain 7:** OAuth Token Abuse → SharePoint/OneDrive Document Theft

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1195.002 | Compromise Software Supply Chain | Initial Access |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1546.003 | WMI Event Subscription Persistence | Persistence |
| T1078.002 | Valid Accounts: Domain Accounts | Privilege Escalation |
| T1484.001 | Group Policy Modification | Privilege Escalation |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | Defense Evasion |
| T1036.005 | Masquerading: Match Legitimate Name | Defense Evasion |
| T1558.001 | Golden Ticket Attack | Credential Access |
| T1003.003 | NTDS.dit Credential Dump | Credential Access |
| T1087.002 | Account Discovery: Domain Account | Discovery |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1572 | Protocol Tunneling C2 | Command & Control |
| T1530 | Data from Cloud Storage | Collection |
| T1048 | Data Exfiltration via C2 | Exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | Golden Ticket Attack (Kerberos Forgery) | 10 |
| 🔴 CRITICAL | NTDS.dit Credential Dump | 10 |
| 🔴 CRITICAL | Data Exfiltration via C2 + Cloud | 20 |
| 🟠 HIGH | Supply Chain Compromise | 15 |
| 🟠 HIGH | WMI Event Subscription Persistence | 15 |
| 🟠 HIGH | Group Policy Modification | 10 |
| 🟠 HIGH | Protocol Tunneling C2 | 20 |
| 🟡 MEDIUM | Rundll32 LOLBin Proxy Execution | 15 |
| 🟡 MEDIUM | Domain Account Discovery | 15 |
| 🟡 MEDIUM | Cloud Storage Data Access (OAuth) | 10 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — Supply chain initial access, PowerShell dropper
- WIN-SOC-PROD-02 — WMI fileless persistence
- WIN-SOC-PROD-03 — Protocol tunneling C2
- WIN-SOC-PROD-04 — Rundll32 LOLBin execution
- WIN-SOC-PROD-05 — LDAP domain enumeration
- WIN-SOC-DC-01 — Golden Ticket, NTDS.dit dump, GPO modification
- WIN-SOC-FILESVR-01 — Dual-channel exfiltration, OAuth cloud theft

**Users**
- WIN-SOC\\Admin, WIN-SOC\\DomainAdmin
- WIN-SOC\\Dev-01, WIN-SOC\\SvcDB, WIN-SOC\\SvcMail
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Reset krbtgt account password TWICE** (72 hours apart) to invalidate all forged Golden Tickets
- **Rebuild WIN-SOC-DC-01** — NTDS.dit compromise means the entire domain credential store is exposed
- **Audit and revert** all GPOs to known-good state; monitor unauthorized GPO creation
- **Block WMI remote access** (DCOM port 135) from non-admin hosts via GPO firewall rules
- **Monitor OAuth token usage** and revoke all refresh tokens for affected accounts
- **Block supply chain update channels** until the compromised package is identified and removed
- **Inspect and quarantine** all endpoints for Rundll32-loaded unsigned DLLs from non-standard paths
- **Isolate all 8 affected hosts** and rotate credentials for all 10 affected accounts immediately

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 91% (CRITICAL)**

| Dimension | Rating |
|-----------|--------|
| Impact | CRITICAL |
| Likelihood | HIGH |
| Severity | CRITICAL |
| Confidence | 97% |
`

  const summary: MockSummary = {
    scan_id: "user-006",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A CRITICAL advanced persistent intrusion was detected in user006logs.csv. Analysis identified 150 threat events across 8 hosts and 7 attack chains. Primary vectors: Supply Chain Compromise, Golden Ticket Attack, NTDS.dit Domain Credential Dump, WMI Fileless Persistence, GPO Mass Deployment, Protocol Tunneling C2, and Dual-Channel Cloud Exfiltration. Risk Score: 91% CRITICAL.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A CRITICAL APT campaign detected in user006logs.csv spanning 7 attack chains. Techniques: Supply Chain (T1195.002), Golden Ticket (T1558.001), NTDS.dit Dump (T1003.003), WMI Persistence (T1546.003), GPO Modification (T1484.001), Protocol Tunneling C2 (T1572), Cloud Exfiltration (T1567.002). Risk Score: 91% CRITICAL.",
      attack_narrative: "Between 2026-04-02 00:18 UTC and 01:05 UTC, a sophisticated threat actor compromised the domain via a trojanized software update. PowerShell droppers established WMI fileless persistence. Rundll32 LOLBin and LDAP enumeration preceded Golden Ticket forgery on WIN-SOC-DC-01. NTDS.dit was extracted exposing all domain credentials. A malicious GPO was deployed domain-wide. Protocol tunneling (HTTPS-over-DNS) provided covert C2. Data was exfiltrated via dual channels: encrypted C2 and an attacker-controlled OneDrive tenant, including SharePoint documents via OAuth token abuse.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01–05, WIN-SOC-DC-01, WIN-SOC-FILESVR-01\n\n**Users:** WIN-SOC\\Admin, WIN-SOC\\DomainAdmin, WIN-SOC\\Dev-01, WIN-SOC\\SvcDB, WIN-SOC\\SvcMail, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Reset krbtgt password twice** (72h apart) to invalidate Golden Tickets.\n2. **Rebuild WIN-SOC-DC-01** — NTDS.dit is fully compromised.\n3. **Revert all GPOs** to known-good snapshots and audit GPO creation rights.\n4. **Revoke all OAuth tokens** and rotate service account credentials.\n5. **Block WMI remote execution** via GPO firewall rules.\n6. **Quarantine supply chain update channel** until compromised package is identified.\n7. **Block C2 IPs and DNS tunneling** patterns at perimeter.\n8. **Isolate all 8 affected hosts** and rotate all 10 account credentials.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER007 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset7/user007logs.json
// Campaign: WMI Fileless Execution with Ransomware Staging — 86% HIGH

function buildUser007Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-007",
    file_name: "user007logs.csv",
    total_logs: 10000,
    total_threats: 180,
    attack_chain_count: 9,
    risk_score: 8600,
    threat_density: 1.8,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u007-01", severity: "critical", title: "WMI Fileless Command Execution — Remote Process Spawn", detection_type: "rule", rule_id: "SOC-T1047-007", mitre_techniques: ["Windows Management Instrumentation"], mitre_ids: ["T1047"], affected_users: ["WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "wmiprvse.exe spawned remote processes via WMI invoke on multiple hosts — fileless execution leaving no disk artifacts, evading traditional AV signature detection.", timestamp: "2026-03-26 23:47:44" },
    { id: "fnd-u007-02", severity: "critical", title: "Ransomware Staging — File Encryption + Shadow Copy Deletion", detection_type: "behavioral", rule_id: "SOC-T1486-007", mitre_techniques: ["Data Encrypted for Impact"], mitre_ids: ["T1486"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-07", "WIN-SOC-PROD-08"], count: 15, description: "Behavioral engine detected ransomware pre-staging: vssadmin deleted shadow copies, bcdedit disabled recovery mode, and mass file encryption began. CPU spiked to 95%. Full ransomware impact imminent.", timestamp: "2026-03-27 01:30:00" },
    { id: "fnd-u007-03", severity: "high", title: "Password Spraying Attack — 4 Accounts Compromised", detection_type: "rule", rule_id: "SOC-T1110-003-007", mitre_techniques: ["Password Spraying"], mitre_ids: ["T1110.003"], affected_users: ["WIN-SOC\\User1", "WIN-SOC\\User2", "WIN-SOC\\Dev-01", "WIN-SOC\\SvcAcct"], affected_hosts: ["WIN-SOC-DC-01"], count: 20, description: "Password spray detected: single password attempted against 150+ accounts over 10 minutes, resulting in 4 successful authentications — evading account lockout by staying under the lockout threshold.", timestamp: "2026-03-26 23:40:00" },
    { id: "fnd-u007-04", severity: "high", title: "UAC Bypass + Thread Execution Hijacking", detection_type: "behavioral", rule_id: "SOC-T1548-002-007", mitre_techniques: ["Bypass UAC via Token Manipulation", "Thread Execution Hijacking"], mitre_ids: ["T1548.002", "T1055.003"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-03"], count: 15, description: "Behavioral engine detected UAC bypass via token manipulation followed by thread execution hijacking into a trusted process — escalating from User to SYSTEM without triggering UAC prompts.", timestamp: "2026-03-26 23:55:00" },
    { id: "fnd-u007-05", severity: "high", title: "RDP Session Hijacking — Active Session Takeover", detection_type: "ml_anomaly", rule_id: "SOC-T1563-002-007", mitre_techniques: ["RDP Hijacking"], mitre_ids: ["T1563.002"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-05", "WIN-SOC-PROD-06"], count: 15, description: "ML model detected tscon.exe used to silently switch to and hijack an active admin RDP session without requiring credentials — classic RDP session hijacking lateral movement technique.", timestamp: "2026-03-27 00:20:00" },
    { id: "fnd-u007-06", severity: "high", title: "BITS Jobs Abused for Persistence + Payload Download", detection_type: "rule", rule_id: "SOC-T1197-007", mitre_techniques: ["BITS Jobs Abuse"], mitre_ids: ["T1197"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-04"], count: 10, description: "Background Intelligent Transfer Service (BITS) was abused to create a persistent job that downloads and executes a malicious payload — BITS jobs survive reboots and are not cleaned by standard AV tools.", timestamp: "2026-03-27 00:05:00" },
    { id: "fnd-u007-07", severity: "medium", title: "Credentials Harvested from Config Files", detection_type: "yara_match", rule_id: "SOC-T1552-001-007", mitre_techniques: ["Credentials in Files"], mitre_ids: ["T1552.001"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-03"], count: 15, description: "YARA rule CRED_IN_FILE_v5 matched access to configuration files containing plaintext credentials — web.config, appsettings.json, and .env files were read and credential material extracted.", timestamp: "2026-03-26 23:58:00" },
    { id: "fnd-u007-08", severity: "medium", title: "Local Account Created for Backdoor Access", detection_type: "rule", rule_id: "SOC-T1136-001-007", mitre_techniques: ["Create Local Account"], mitre_ids: ["T1136.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-09", "WIN-SOC-PROD-10"], count: 10, description: "net user commands created new local accounts with admin rights on 2 hosts — establishing a backdoor access mechanism independent of domain credentials.", timestamp: "2026-03-27 00:30:00" },
    { id: "fnd-u007-09", severity: "medium", title: "Network Share + File Directory Discovery", detection_type: "heuristic", rule_id: "SOC-T1135-007", mitre_techniques: ["Network Share Discovery", "File and Directory Discovery"], mitre_ids: ["T1135", "T1083"], affected_users: ["WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01"], count: 30, description: "Heuristic engine detected rapid sequential net share, net view, and dir enumeration commands — systematic network share discovery preceding data staging.", timestamp: "2026-03-26 23:50:00" },
    { id: "fnd-u007-10", severity: "medium", title: "Remote Data Staging via Network Share Copy", detection_type: "ml_anomaly", rule_id: "SOC-T1074-002-007", mitre_techniques: ["Remote Data Staging"], mitre_ids: ["T1074.002"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-FILESVR-01"], count: 15, description: "ML model flagged mass data copy from network shares to a remote staging location — 8.3-sigma I/O anomaly, 120 MB/s sustained transfer consistent with pre-exfiltration data aggregation.", timestamp: "2026-03-27 01:00:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-007-01", chain_index: 1, title: "Password Spraying → WMI Fileless Remote Execution", computer: "WIN-SOC-PROD-02", chain_confidence: 0.95, kill_chain_phases: ["initial-access", "execution"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\User1", "WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-007-log-1", "fnd-ds-007-log-2"] },
    { chain_id: "chain-ds-007-02", chain_index: 2, title: "Credentials in Files → UAC Bypass → Thread Hijacking", computer: "WIN-SOC-PROD-03", chain_confidence: 0.92, kill_chain_phases: ["credential-access", "privilege-escalation"], affected_users: ["WIN-SOC\\Dev-01", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-03"], events: ["fnd-ds-007-log-3"] },
    { chain_id: "chain-ds-007-03", chain_index: 3, title: "BITS Jobs Persistence + Payload Download", computer: "WIN-SOC-PROD-04", chain_confidence: 0.90, kill_chain_phases: ["persistence", "command-and-control"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-04"], events: ["fnd-ds-007-log-4"] },
    { chain_id: "chain-ds-007-04", chain_index: 4, title: "Network Share Discovery → Remote Data Staging", computer: "WIN-SOC-PROD-01", chain_confidence: 0.88, kill_chain_phases: ["discovery", "collection"], affected_users: ["WIN-SOC\\User1", "WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-FILESVR-01"], events: ["fnd-ds-007-log-5"] },
    { chain_id: "chain-ds-007-05", chain_index: 5, title: "RDP Session Hijacking — Admin Takeover", computer: "WIN-SOC-PROD-05", chain_confidence: 0.93, kill_chain_phases: ["lateral-movement"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-05", "WIN-SOC-PROD-06"], events: ["fnd-ds-007-log-6"] },
    { chain_id: "chain-ds-007-06", chain_index: 6, title: "Local Backdoor Accounts Created on PROD-09 & PROD-10", computer: "WIN-SOC-PROD-09", chain_confidence: 0.87, kill_chain_phases: ["persistence"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-09", "WIN-SOC-PROD-10"], events: ["fnd-ds-007-log-7"] },
    { chain_id: "chain-ds-007-07", chain_index: 7, title: "Software Packing + Event Log Disable — Defense Evasion", computer: "WIN-SOC-PROD-02", chain_confidence: 0.89, kill_chain_phases: ["defense-evasion"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02"], events: ["fnd-ds-007-log-8"] },
    { chain_id: "chain-ds-007-08", chain_index: 8, title: "Ransomware Pre-Staging — Shadow Copy Deletion + Encryption", computer: "WIN-SOC-PROD-07", chain_confidence: 0.99, kill_chain_phases: ["defense-evasion", "impact"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-07", "WIN-SOC-PROD-08"], events: ["fnd-ds-007-log-9"] },
    { chain_id: "chain-ds-007-09", chain_index: 9, title: "Removable Media C2 Communication Channel", computer: "WIN-SOC-PROD-06", chain_confidence: 0.85, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\SvcAcct"], affected_hosts: ["WIN-SOC-PROD-06"], events: ["fnd-ds-007-log-10"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user007logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🟠 HIGH (86%) |
| Total Logs | 10,000 |
| Threat Events | 180 |
| Attack Chains | 9 |
| Affected Hosts | 10 |
| Affected Users | 12 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **high-severity multi-stage intrusion campaign** was detected in **user007logs.csv** spanning **9 distinct attack chains** across 11 MITRE ATT&CK tactic categories.

The adversary leveraged WMI for fileless execution, abused trusted BITS jobs for persistence, conducted RDP session hijacking, and staged a full ransomware pre-deployment sequence.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-10** and **WIN-SOC-FILESVR-01**

Immediate containment, host isolation, and full forensic investigation are required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-03-26 23:40:00 | WIN-SOC-DC-01 | Password Spraying — 4 Accounts Compromised |
| 2026-03-26 23:47:42 | WIN-SOC-PROD-02 | WMI Fileless Remote Process Spawned |
| 2026-03-26 23:50:00 | WIN-SOC-PROD-01 | Network Share + Directory Discovery |
| 2026-03-26 23:55:00 | WIN-SOC-PROD-03 | UAC Bypass + Thread Execution Hijacking |
| 2026-03-26 23:58:00 | WIN-SOC-PROD-03 | Credentials Harvested from Config Files |
| 2026-03-27 00:05:00 | WIN-SOC-PROD-04 | BITS Jobs Persistence + Payload Download |
| 2026-03-27 00:20:00 | WIN-SOC-PROD-05 | RDP Session Hijacking (tscon.exe) |
| 2026-03-27 00:30:00 | WIN-SOC-PROD-09 | Local Backdoor Accounts Created |
| 2026-03-27 01:00:00 | WIN-SOC-FILESVR-01 | Remote Data Staging via Network Share |
| 2026-03-27 01:30:00 | WIN-SOC-PROD-07 | Ransomware Staging — Shadow Copy Deleted |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** Password Spraying → Compromised Credentials → WMI Fileless Remote Execution
- **Chain 2:** Credentials in Config Files → UAC Bypass → Thread Execution Hijacking → SYSTEM
- **Chain 3:** BITS Jobs Abuse — Persistent Payload Download & Execution
- **Chain 4:** Network Share Discovery → Remote Data Staging (pre-exfiltration)
- **Chain 5:** RDP Session Hijacking — Admin Session Takeover via tscon.exe
- **Chain 6:** Local Backdoor Accounts Created on PROD-09 and PROD-10
- **Chain 7:** Software Packing + Event Log Disablement — Defense Evasion
- **Chain 8:** Ransomware Pre-Staging — Shadow Copy Deletion + Mass File Encryption
- **Chain 9:** Removable Media C2 — Covert Command Channel via USB

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1566.002 | Spearphishing Link | Initial Access |
| T1110.003 | Password Spraying | Credential Access |
| T1047 | WMI Command Execution | Execution |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1136.001 | Create Local Account | Persistence |
| T1197 | BITS Jobs Abuse | Persistence |
| T1548.002 | Bypass UAC via Token Manipulation | Privilege Escalation |
| T1055.003 | Thread Execution Hijacking | Privilege Escalation |
| T1562.002 | Disable Windows Event Logging | Defense Evasion |
| T1027.002 | Software Packing | Defense Evasion |
| T1552.001 | Credentials in Files | Credential Access |
| T1083 | File and Directory Discovery | Discovery |
| T1135 | Network Share Discovery | Discovery |
| T1563.002 | RDP Hijacking | Lateral Movement |
| T1092 | Communication via Removable Media | Command & Control |
| T1074.002 | Remote Data Staging | Collection |
| T1486 | Data Encrypted for Impact (Ransomware) | Impact |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | WMI Fileless Command Execution | 20 |
| 🔴 CRITICAL | Ransomware Staging + File Encryption | 15 |
| 🟠 HIGH | Password Spraying Attack | 20 |
| 🟠 HIGH | UAC Bypass + Thread Hijacking | 15 |
| 🟠 HIGH | RDP Session Hijacking | 15 |
| 🟠 HIGH | BITS Jobs Abuse for Persistence | 10 |
| 🟡 MEDIUM | Credentials Harvested from Config Files | 15 |
| 🟡 MEDIUM | Local Backdoor Accounts Created | 10 |
| 🟡 MEDIUM | Network Share + Directory Discovery | 30 |
| 🟡 MEDIUM | Remote Data Staging | 15 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — WMI execution origin, share discovery
- WIN-SOC-PROD-02 — WMI execution target, event log disabled
- WIN-SOC-PROD-03 — UAC bypass, thread hijacking, credential file access
- WIN-SOC-PROD-04 — BITS jobs persistence
- WIN-SOC-PROD-05 — RDP hijacking source
- WIN-SOC-PROD-06 — RDP hijacking target, removable media C2
- WIN-SOC-PROD-07/08 — Ransomware staging and encryption
- WIN-SOC-PROD-09/10 — Backdoor local accounts
- WIN-SOC-FILESVR-01 — Remote data staging
- WIN-SOC-DC-01 — Password spray target

**Users**
- WIN-SOC\\Admin, WIN-SOC\\User1, WIN-SOC\\User2
- WIN-SOC\\Dev-01, WIN-SOC\\SvcAcct, NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Immediately isolate WIN-SOC-PROD-07/08** — ransomware encryption may still be in progress
- **Enable LAPS** and enforce complex password policies to defeat password spraying
- **Restrict WMI remote access** via GPO (block DCOM port 135 from non-admin hosts)
- **Audit and remove all BITS jobs** across all endpoints — delete unauthorized transfer jobs
- **Block tscon.exe** from non-SYSTEM processes to prevent RDP session hijacking
- **Remove backdoor local accounts** created by NT AUTHORITY\\SYSTEM on PROD-09/10
- **Restore shadow copies** from an offline backup — all local shadow copies have been deleted
- **Scan all config/env files** for exposed credentials and rotate any found credentials
- **Isolate all 10 affected hosts** and rotate credentials for all 12 affected accounts

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 86% (HIGH)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | HIGH |
| Confidence | 95% |
`

  const summary: MockSummary = {
    scan_id: "user-007",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A HIGH-severity multi-stage intrusion was detected in user007logs.csv. Analysis identified 180 threat events across 10 hosts and 9 attack chains. Primary vectors: Password Spraying, WMI Fileless Execution, UAC Bypass, BITS Persistence, RDP Session Hijacking, and Ransomware Pre-Staging with Shadow Copy Deletion. Risk Score: 86% HIGH.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A HIGH-severity multi-stage intrusion campaign was detected in user007logs.csv spanning 9 attack chains. Techniques: Password Spraying (T1110.003), WMI Fileless Execution (T1047), UAC Bypass (T1548.002), Thread Hijacking (T1055.003), BITS Persistence (T1197), RDP Hijacking (T1563.002), Ransomware Impact (T1486). Risk Score: 86% HIGH.",
      attack_narrative: "Between 2026-03-26 23:40 UTC and 2026-03-27 01:30 UTC, a threat actor executed a 9-chain campaign. Password spraying compromised 4 accounts. WMI fileless execution spread laterally across PROD-01 and PROD-02. UAC bypass and thread hijacking escalated to SYSTEM on PROD-03. BITS jobs created persistent payload download. RDP session hijacking moved laterally. Remote data was staged from network shares. Backdoor local accounts were created on PROD-09/10. Ransomware pre-staging began on PROD-07/08 with shadow copy deletion and mass file encryption.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-10, WIN-SOC-FILESVR-01, WIN-SOC-DC-01\n\n**Users:** WIN-SOC\\Admin, WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\Dev-01, WIN-SOC\\SvcAcct, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Isolate WIN-SOC-PROD-07/08** immediately — ransomware may be encrypting files.\n2. **Enable LAPS** and enforce 14+ character passwords to defeat password spraying.\n3. **Block WMI remote access** (DCOM port 135) via GPO.\n4. **Audit and delete all unauthorized BITS jobs** across all endpoints.\n5. **Restrict tscon.exe** to prevent RDP hijacking.\n6. **Remove backdoor accounts** on PROD-09/10.\n7. **Restore from offline backup** — all shadow copies have been deleted.\n8. **Rotate credentials** for all 12 affected accounts.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER008 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset8/user008logs.json
// Campaign: Credential-Based Intrusion via Pass-the-Hash & LSA Secrets — 63% MEDIUM

function buildUser008Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-008",
    file_name: "user008logs.csv",
    total_logs: 10000,
    total_threats: 155,
    attack_chain_count: 8,
    risk_score: 6300,
    threat_density: 1.55,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u008-01", severity: "critical", title: "Pass-the-Hash NTLM Lateral Authentication", detection_type: "ml_anomaly", rule_id: "SOC-T1550-002-008", mitre_techniques: ["Use Alternate Authentication Material: Pass the Hash"], mitre_ids: ["T1550.002"], affected_users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "ML model flagged NTLM Type 3 logon without preceding Kerberos negotiation across 3 host pairs — 8.7-sigma deviation. Pass-the-Hash lateral movement confirmed across the production subnet.", timestamp: "2026-04-03 00:19:30" },
    { id: "fnd-u008-02", severity: "high", title: "LSA Secrets Dump — Service Account Credential Extraction", detection_type: "behavioral", rule_id: "SOC-T1003-004-008", mitre_techniques: ["OS Credential Dumping: LSA Secrets"], mitre_ids: ["T1003.004"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-03"], count: 15, description: "Behavioral engine flagged reg.exe extracting the LSA Secrets registry hive — service account credentials, autologon passwords, and cached domain credentials harvested.", timestamp: "2026-04-03 00:22:00" },
    { id: "fnd-u008-03", severity: "high", title: "DLL Side-Loading Persistence — Unsigned DLL in System32 Lookalike", detection_type: "yara_match", rule_id: "SOC-T1574-002-008", mitre_techniques: ["Hijack Execution Flow: DLL Side-Loading"], mitre_ids: ["T1574.002"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-PROD-04", "WIN-SOC-PROD-05"], count: 15, description: "YARA rule DLL_SIDELOAD_v3 matched an unsigned DLL loaded by a legitimate signed binary from a path masquerading as System32 — classic DLL side-loading for persistent code execution.", timestamp: "2026-04-03 00:30:00" },
    { id: "fnd-u008-04", severity: "high", title: "WinRM Lateral Movement — Remote Command Execution", detection_type: "rule", rule_id: "SOC-T1021-006-008", mitre_techniques: ["Windows Remote Management (WinRM)"], mitre_ids: ["T1021.006"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-06", "WIN-SOC-PROD-07"], count: 15, description: "Invoke-Command via WinRM (port 5985) used to execute commands on PROD-06 and PROD-07 — PowerShell remoting leveraged for lateral movement using harvested credentials.", timestamp: "2026-04-03 00:40:00" },
    { id: "fnd-u008-05", severity: "medium", title: "PowerShell Encoded Execution + WMI Command", detection_type: "rule", rule_id: "SOC-T1059-001-008", mitre_techniques: ["PowerShell Encoded Command Execution", "WMI Command Execution"], mitre_ids: ["T1059.001", "T1047"], affected_users: ["NT AUTHORITY\\SYSTEM", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "Encoded PowerShell IEX and WMI process creation used in combination — multi-stage execution chain to bypass logging and AV detection.", timestamp: "2026-04-03 00:19:32" },
    { id: "fnd-u008-06", severity: "medium", title: "Web Shell Persistence — ASPX Shell on IIS Server", detection_type: "yara_match", rule_id: "SOC-T1505-003-008", mitre_techniques: ["Server Software Component: Web Shell"], mitre_ids: ["T1505.003"], affected_users: ["WIN-SOC\\SvcWeb"], affected_hosts: ["WIN-SOC-WEB-01"], count: 15, description: "YARA rule WEBSHELL_ASPX_v4 matched a malicious ASPX file uploaded to IIS — providing a persistent web-accessible backdoor that bypasses traditional endpoint controls.", timestamp: "2026-04-03 00:50:00" },
    { id: "fnd-u008-07", severity: "medium", title: "Timestomping — File Modification Timestamps Altered", detection_type: "behavioral", rule_id: "SOC-T1070-006-008", mitre_techniques: ["Indicator Removal: Timestomping"], mitre_ids: ["T1070.006"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-04"], count: 15, description: "Behavioral engine detected file creation/modification timestamps on malicious DLLs being altered to match legitimate system files — anti-forensic timestomping to confuse incident timelines.", timestamp: "2026-04-03 00:32:00" },
    { id: "fnd-u008-08", severity: "medium", title: "External Proxy C2 — Traffic Routed via Tor Exit", detection_type: "ml_anomaly", rule_id: "SOC-T1090-002-008", mitre_techniques: ["Proxy: External Proxy C2"], mitre_ids: ["T1090.002"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-PROD-08"], count: 20, description: "ML model detected C2 traffic routed through an external proxy chain terminating at a known Tor exit node — evading IP-based threat intelligence blocking with rotating exit IPs.", timestamp: "2026-04-03 01:00:00" },
    { id: "fnd-u008-09", severity: "low", title: "Domain Group Enumeration — LDAP AD Query", detection_type: "rule", rule_id: "SOC-T1069-002-008", mitre_techniques: ["Permission Groups Discovery: Domain Groups"], mitre_ids: ["T1069.002"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-02"], count: 10, description: "LDAP queries enumerating domain security groups and group memberships — post-exploitation AD reconnaissance to identify privileged group targets.", timestamp: "2026-04-03 00:25:00" },
    { id: "fnd-u008-10", severity: "low", title: "Clipboard Data Collection — Keylogger-style Data Theft", detection_type: "behavioral", rule_id: "SOC-T1115-008", mitre_techniques: ["Clipboard Data Collection"], mitre_ids: ["T1115"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-09"], count: 10, description: "Behavioral engine detected periodic clipboard access by a non-standard process — clipboard data collection harvesting passwords, URLs, and sensitive content copied by the user.", timestamp: "2026-04-03 01:15:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-008-01", chain_index: 1, title: "PowerShell + WMI Execution → Pass-the-Hash Lateral Movement", computer: "WIN-SOC-PROD-01", chain_confidence: 0.93, kill_chain_phases: ["execution", "lateral-movement"], affected_users: ["NT AUTHORITY\\SYSTEM", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-008-log-1", "fnd-ds-008-log-2"] },
    { chain_id: "chain-ds-008-02", chain_index: 2, title: "LSA Secrets Dump — Service Account Credential Extraction", computer: "WIN-SOC-PROD-03", chain_confidence: 0.91, kill_chain_phases: ["credential-access"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-03"], events: ["fnd-ds-008-log-3"] },
    { chain_id: "chain-ds-008-03", chain_index: 3, title: "Domain Group LDAP Enumeration", computer: "WIN-SOC-PROD-02", chain_confidence: 0.87, kill_chain_phases: ["discovery"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-02"], events: ["fnd-ds-008-log-4"] },
    { chain_id: "chain-ds-008-04", chain_index: 4, title: "DLL Side-Loading Persistence + Timestomping", computer: "WIN-SOC-PROD-04", chain_confidence: 0.92, kill_chain_phases: ["persistence", "defense-evasion"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-PROD-04", "WIN-SOC-PROD-05"], events: ["fnd-ds-008-log-5"] },
    { chain_id: "chain-ds-008-05", chain_index: 5, title: "WinRM Remote Command Execution — Lateral Movement", computer: "WIN-SOC-PROD-06", chain_confidence: 0.90, kill_chain_phases: ["lateral-movement"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-06", "WIN-SOC-PROD-07"], events: ["fnd-ds-008-log-6"] },
    { chain_id: "chain-ds-008-06", chain_index: 6, title: "Web Shell Persistence on IIS Server", computer: "WIN-SOC-WEB-01", chain_confidence: 0.88, kill_chain_phases: ["persistence", "command-and-control"], affected_users: ["WIN-SOC\\SvcWeb"], affected_hosts: ["WIN-SOC-WEB-01"], events: ["fnd-ds-008-log-7"] },
    { chain_id: "chain-ds-008-07", chain_index: 7, title: "External Proxy C2 via Tor Exit Node", computer: "WIN-SOC-PROD-08", chain_confidence: 0.89, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\SvcDB"], affected_hosts: ["WIN-SOC-PROD-08"], events: ["fnd-ds-008-log-8"] },
    { chain_id: "chain-ds-008-08", chain_index: 8, title: "Clipboard Data Collection + Environmental Keying Evasion", computer: "WIN-SOC-PROD-09", chain_confidence: 0.85, kill_chain_phases: ["collection", "defense-evasion"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-09"], events: ["fnd-ds-008-log-9"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user008logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🟡 MEDIUM (63%) |
| Total Logs | 10,000 |
| Threat Events | 155 |
| Attack Chains | 8 |
| Affected Hosts | 9 |
| Affected Users | 11 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **medium-severity credential-focused intrusion campaign** was detected in **user008logs.csv** spanning **8 distinct attack chains** across 9 MITRE ATT&CK tactic categories.

The adversary relied on stolen NTLM hashes (Pass-the-Hash), LSA Secrets extraction, DLL side-loading for stealthy persistence, WinRM lateral movement, and Tor-proxied C2 communication to avoid detection.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-09** and **WIN-SOC-WEB-01**

Containment, credential rotation, and review of privileged access controls are recommended.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-03 00:19:30 | WIN-SOC-PROD-01 | PowerShell IEX + WMI Execution |
| 2026-04-03 00:19:32 | WIN-SOC-PROD-01 | Pass-the-Hash NTLM Lateral Movement |
| 2026-04-03 00:22:00 | WIN-SOC-PROD-03 | LSA Secrets Registry Hive Extracted |
| 2026-04-03 00:25:00 | WIN-SOC-PROD-02 | Domain Group LDAP Enumeration |
| 2026-04-03 00:30:00 | WIN-SOC-PROD-04 | DLL Side-Loading — Unsigned DLL Loaded |
| 2026-04-03 00:32:00 | WIN-SOC-PROD-04 | Timestomping — File Timestamps Altered |
| 2026-04-03 00:40:00 | WIN-SOC-PROD-06 | WinRM Lateral Movement — Remote Commands |
| 2026-04-03 00:50:00 | WIN-SOC-WEB-01 | Web Shell Uploaded to IIS Server |
| 2026-04-03 01:00:00 | WIN-SOC-PROD-08 | External Proxy C2 via Tor Exit Node |
| 2026-04-03 01:15:00 | WIN-SOC-PROD-09 | Clipboard Data Collection Initiated |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** PowerShell Encoded + WMI Execution → Pass-the-Hash NTLM Lateral Movement
- **Chain 2:** LSA Secrets Dump — Service Account + Cached Credential Extraction
- **Chain 3:** Domain Group LDAP Enumeration (Post-Exploitation AD Recon)
- **Chain 4:** DLL Side-Loading Persistence + Timestomping Anti-Forensics
- **Chain 5:** WinRM Remote Command Execution — Lateral Movement via PowerShell Remoting
- **Chain 6:** ASPX Web Shell Persistence on IIS Server
- **Chain 7:** External Proxy C2 via Tor Exit Node (Rotating IPs)
- **Chain 8:** Clipboard Data Collection + Environmental Keying Evasion

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1047 | WMI Command Execution | Execution |
| T1505.003 | Web Shell Persistence | Persistence |
| T1574.002 | DLL Side-Loading | Persistence |
| T1134.002 | Create Process with Token | Privilege Escalation |
| T1480.001 | Environmental Keying (Execution Guardrails) | Defense Evasion |
| T1070.006 | Timestomping | Defense Evasion |
| T1550.002 | Pass-the-Hash Attack | Credential Access |
| T1003.004 | LSA Secrets Dump | Credential Access |
| T1069.002 | Permission Groups Discovery: Domain Groups | Discovery |
| T1021.006 | Windows Remote Management (WinRM) | Lateral Movement |
| T1090.002 | External Proxy C2 | Command & Control |
| T1115 | Clipboard Data Collection | Collection |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | Pass-the-Hash NTLM Lateral Authentication | 20 |
| 🟠 HIGH | LSA Secrets Dump | 15 |
| 🟠 HIGH | DLL Side-Loading Persistence | 15 |
| 🟠 HIGH | WinRM Lateral Movement | 15 |
| 🟡 MEDIUM | PowerShell + WMI Execution | 20 |
| 🟡 MEDIUM | Web Shell on IIS | 15 |
| 🟡 MEDIUM | Timestomping Defense Evasion | 15 |
| 🟡 MEDIUM | External Proxy C2 (Tor) | 20 |
| 🔵 LOW | Domain Group Enumeration | 10 |
| 🔵 LOW | Clipboard Data Collection | 10 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01/02 — PowerShell/WMI execution, Pass-the-Hash origin/target
- WIN-SOC-PROD-03 — LSA Secrets extraction
- WIN-SOC-PROD-04/05 — DLL side-loading, timestomping
- WIN-SOC-PROD-06/07 — WinRM lateral movement targets
- WIN-SOC-PROD-08 — Tor-proxied C2
- WIN-SOC-PROD-09 — Clipboard data collection
- WIN-SOC-WEB-01 — ASPX web shell persistence

**Users**
- WIN-SOC\\User1, WIN-SOC\\User3
- WIN-SOC\\Admin, WIN-SOC\\SvcDB, WIN-SOC\\SvcWeb
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Enable Credential Guard** to prevent Pass-the-Hash and NTLM hash extraction
- **Restrict WinRM access** to management jump hosts only via network ACLs
- **Audit all IIS virtual directories** for unauthorized ASPX files and remove web shells
- **Enable DLL monitoring** and application whitelisting to block unsigned DLL side-loading
- **Block Tor exit node IPs** at perimeter and monitor for proxy-chained C2 patterns
- **Rotate LSA Secrets** — reset all service account credentials stored in LSA
- **Deploy forensic timeline tools** to detect timestomping on modified files
- **Monitor clipboard access** by non-standard processes via EDR behavioral rules
- **Rotate credentials** for all 11 affected accounts and review privileged access

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 63% (MEDIUM)**

| Dimension | Rating |
|-----------|--------|
| Impact | MEDIUM |
| Likelihood | HIGH |
| Severity | MEDIUM |
| Confidence | 91% |
`

  const summary: MockSummary = {
    scan_id: "user-008",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A MEDIUM-severity credential-focused intrusion was detected in user008logs.csv. Analysis identified 155 threat events across 9 hosts and 8 attack chains. Primary vectors: Pass-the-Hash Lateral Movement, LSA Secrets Dump, DLL Side-Loading, WinRM Lateral Movement, Web Shell Persistence, and Tor-proxied C2. Risk Score: 63% MEDIUM.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A MEDIUM-severity credential-based intrusion campaign detected in user008logs.csv spanning 8 attack chains. Techniques: Pass-the-Hash (T1550.002), LSA Secrets Dump (T1003.004), DLL Side-Loading (T1574.002), WinRM Lateral Movement (T1021.006), Web Shell (T1505.003), External Proxy C2 (T1090.002). Risk Score: 63% MEDIUM.",
      attack_narrative: "Between 2026-04-03 00:19 UTC and 01:15 UTC, a stealthy threat actor executed an 8-chain credential-focused campaign. PowerShell/WMI execution was followed by Pass-the-Hash lateral movement using stolen NTLM hashes. LSA Secrets were extracted from WIN-SOC-PROD-03. DLL side-loading established stealthy persistence with timestomping to defeat forensic timelines. WinRM remote execution laterally moved to PROD-06/07. An ASPX web shell was uploaded to the IIS server as a persistent backdoor. C2 communication was routed via Tor exit nodes with environmental keying for evasion. Clipboard data was silently collected on PROD-09.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-09, WIN-SOC-WEB-01\n\n**Users:** WIN-SOC\\User1, WIN-SOC\\User3, WIN-SOC\\Admin, WIN-SOC\\SvcDB, WIN-SOC\\SvcWeb, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Enable Credential Guard** to block Pass-the-Hash and NTLM extraction.\n2. **Reset all LSA Secrets** — rotate all service account credentials.\n3. **Restrict WinRM** to management hosts only via network ACLs.\n4. **Scan IIS directories** for ASPX web shells and remove immediately.\n5. **Block Tor exit nodes** at perimeter firewall.\n6. **Deploy DLL whitelisting** to block unsigned DLL loading.\n7. **Run forensic timestamp analysis** to identify all tampered files.\n8. **Rotate credentials** for all 11 affected accounts.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER009 LOGS JSON DATASET ────────────────────────────────────────────────
// Derived from /datasets/dataset9/user009logs.json
// Campaign: APT-Level DC Compromise — DCSync, Skeleton Key, PrintNightmare — 95% CRITICAL

function buildUser009Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-009",
    file_name: "user009logs.csv",
    total_logs: 10000,
    total_threats: 200,
    attack_chain_count: 10,
    risk_score: 9500,
    threat_density: 2.0,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u009-01", severity: "critical", title: "DCSync Replication Attack — Full AD Credential Harvest", detection_type: "ml_anomaly", rule_id: "SOC-T1003-006-009", mitre_techniques: ["OS Credential Dumping: DCSync"], mitre_ids: ["T1003.006"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-DC-01"], count: 15, description: "ML model detected MS-DRSR GetNCChanges replication requests from a non-DC endpoint (WIN-SOC-PROD-02) — 10-sigma anomaly. All domain hashes including krbtgt extracted. Full AD credential compromise confirmed.", timestamp: "2026-04-03 00:05:26" },
    { id: "fnd-u009-02", severity: "critical", title: "Skeleton Key Malware Implanted on Domain Controller", detection_type: "yara_match", rule_id: "SOC-T1556-001-009", mitre_techniques: ["Modify Authentication Process: Domain Controller Authentication"], mitre_ids: ["T1556.001"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-DC-01"], count: 10, description: "YARA rule SKELETON_KEY_v2 matched mimikatz skeleton key injection into lsass.exe on WIN-SOC-DC-01 — ANY account can now authenticate with password 'mimikatz'. Requires immediate DC rebuild.", timestamp: "2026-04-03 00:15:00" },
    { id: "fnd-u009-03", severity: "critical", title: "PrintNightmare Privilege Escalation (CVE-2021-34527)", detection_type: "rule", rule_id: "SOC-T1068-PRINTNIGHTMARE", mitre_techniques: ["Exploitation for Privilege Escalation: PrintNightmare"], mitre_ids: ["T1068"], affected_users: ["WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-03", "WIN-SOC-PROD-04"], count: 15, description: "Print Spooler service exploited via CVE-2021-34527 (PrintNightmare) — attacker loaded an unsigned malicious DLL via AddPrinterDriverEx, escalating to SYSTEM without valid credentials.", timestamp: "2026-04-03 00:08:00" },
    { id: "fnd-u009-04", severity: "critical", title: "DPAPI Master Key Theft — Browser + Vault Credential Access", detection_type: "behavioral", rule_id: "SOC-T1555-003-009", mitre_techniques: ["Credentials from Password Stores: DPAPI"], mitre_ids: ["T1555.003"], affected_users: ["WIN-SOC\\User3", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-05"], count: 10, description: "Behavioral engine detected DPAPI master key extraction via dpapi.py — Chrome saved passwords, Windows Credential Manager vaults, and Outlook credential stores all decrypted.", timestamp: "2026-04-03 00:25:00" },
    { id: "fnd-u009-05", severity: "high", title: "VPN Credential Abuse — Unauthorized External Access", detection_type: "rule", rule_id: "SOC-T1133-009", mitre_techniques: ["External Remote Services: VPN Abuse"], mitre_ids: ["T1133"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-VPN-01"], count: 15, description: "Successful VPN authentication detected from an IP in an unusual geolocation using valid credentials obtained from DPAPI theft — external initial access via stolen VPN credentials.", timestamp: "2026-04-02 23:55:00" },
    { id: "fnd-u009-06", severity: "high", title: "Process Doppelganging — Anti-Forensic Defense Evasion", detection_type: "ml_anomaly", rule_id: "SOC-T1055-012-009", mitre_techniques: ["Process Doppelganging"], mitre_ids: ["T1055.012"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-06"], count: 15, description: "ML model detected process doppelganging: malicious code injected into a transaction-pending NTFS file — the resulting process appears as a legitimate binary with no disk artifact, evading EDR scanning.", timestamp: "2026-04-03 00:20:00" },
    { id: "fnd-u009-07", severity: "high", title: "SSH Session Hijacking — Active Session Takeover", detection_type: "rule", rule_id: "SOC-T1563-001-009", mitre_techniques: ["SSH Hijacking for Lateral Movement"], mitre_ids: ["T1563.001"], affected_users: ["WIN-SOC\\DBAdmin"], affected_hosts: ["WIN-SOC-LINUX-01", "WIN-SOC-LINUX-02"], count: 15, description: "SSH agent socket hijacking detected via ptrace — attacker used an active privileged SSH session belonging to DBAdmin to pivot to Linux hosts without needing SSH private keys.", timestamp: "2026-04-03 00:35:00" },
    { id: "fnd-u009-08", severity: "high", title: "ICMP Tunneling C2 — Covert Command Channel", detection_type: "ml_anomaly", rule_id: "SOC-T1095-009", mitre_techniques: ["Non-Application Layer Protocol: ICMP C2"], mitre_ids: ["T1095"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-07"], count: 20, description: "ML model detected anomalous ICMP echo request/reply patterns with variable-length payloads (300–1400 bytes) and 8-second intervals — ICMP tunneling C2 evading application-layer inspection.", timestamp: "2026-04-03 00:30:00" },
    { id: "fnd-u009-09", severity: "medium", title: "DNS Reconnaissance — Victim Network Information Gathering", detection_type: "heuristic", rule_id: "SOC-T1590-002-009", mitre_techniques: ["Gather Victim Network Information: DNS"], mitre_ids: ["T1590.002"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-01"], count: 20, description: "Heuristic engine detected DNS zone transfer attempts, reverse DNS lookups, and subdomain enumeration — pre-attack network reconnaissance targeting internal naming conventions.", timestamp: "2026-04-02 23:45:00" },
    { id: "fnd-u009-10", severity: "medium", title: "Domain Trust + Cloud Service Discovery", detection_type: "rule", rule_id: "SOC-T1482-009", mitre_techniques: ["Domain Trust Discovery", "Cloud Service Discovery"], mitre_ids: ["T1482", "T1526"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-02"], count: 30, description: "Domain trust enumeration and cloud service discovery (AWS/Azure metadata endpoints) detected — attacker mapping cross-domain trust relationships and cloud resource inventory for lateral expansion.", timestamp: "2026-04-03 00:10:00" },
    { id: "fnd-u009-11", severity: "medium", title: "Audio Capture Collection — Microphone Eavesdropping", detection_type: "behavioral", rule_id: "SOC-T1123-009", mitre_techniques: ["Audio Capture"], mitre_ids: ["T1123"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-PROD-08"], count: 15, description: "Behavioral engine detected unauthorized microphone access by a background process — audio capture recording executive calls for intelligence collection.", timestamp: "2026-04-03 01:00:00" },
    { id: "fnd-u009-12", severity: "medium", title: "Scheduled Nightly Transfer — Covert Exfiltration Beacon", detection_type: "ml_anomaly", rule_id: "SOC-T1029-009", mitre_techniques: ["Scheduled Transfer: Nightly Exfil Beacon"], mitre_ids: ["T1029"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-09"], count: 15, description: "ML model detected low-volume scheduled nightly data transfers (2 AM UTC) over HTTPS — small-packet exfiltration timed to blend with maintenance window traffic to avoid anomaly detection.", timestamp: "2026-04-03 02:00:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-009-01", chain_index: 1, title: "DNS Recon → VPN Credential Abuse → Initial Access", computer: "WIN-SOC-VPN-01", chain_confidence: 0.93, kill_chain_phases: ["reconnaissance", "initial-access"], affected_users: ["WIN-SOC\\User3"], affected_hosts: ["WIN-SOC-VPN-01", "WIN-SOC-PROD-01"], events: ["fnd-ds-009-log-1"] },
    { chain_id: "chain-ds-009-02", chain_index: 2, title: "PowerShell Dropper → Domain Trust Discovery → DCSync", computer: "WIN-SOC-PROD-02", chain_confidence: 0.99, kill_chain_phases: ["execution", "discovery", "credential-access"], affected_users: ["WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-DC-01"], events: ["fnd-ds-009-log-2", "fnd-ds-009-log-3"] },
    { chain_id: "chain-ds-009-03", chain_index: 3, title: "PrintNightmare Exploit → SYSTEM Privilege Escalation", computer: "WIN-SOC-PROD-03", chain_confidence: 0.98, kill_chain_phases: ["privilege-escalation"], affected_users: ["WIN-SOC\\Admin", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-03", "WIN-SOC-PROD-04"], events: ["fnd-ds-009-log-4"] },
    { chain_id: "chain-ds-009-04", chain_index: 4, title: "Skeleton Key Implanted on Domain Controller", computer: "WIN-SOC-DC-01", chain_confidence: 0.99, kill_chain_phases: ["persistence"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-DC-01"], events: ["fnd-ds-009-log-5"] },
    { chain_id: "chain-ds-009-05", chain_index: 5, title: "Process Doppelganging — Fileless Defense Evasion", computer: "WIN-SOC-PROD-06", chain_confidence: 0.94, kill_chain_phases: ["defense-evasion"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-06"], events: ["fnd-ds-009-log-6"] },
    { chain_id: "chain-ds-009-06", chain_index: 6, title: "DPAPI Master Key Theft — Browser + Vault Credentials", computer: "WIN-SOC-PROD-05", chain_confidence: 0.97, kill_chain_phases: ["credential-access"], affected_users: ["WIN-SOC\\User3", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-05"], events: ["fnd-ds-009-log-7"] },
    { chain_id: "chain-ds-009-07", chain_index: 7, title: "ICMP Tunneling C2 — Covert Encrypted Command Channel", computer: "WIN-SOC-PROD-07", chain_confidence: 0.95, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-07"], events: ["fnd-ds-009-log-8"] },
    { chain_id: "chain-ds-009-08", chain_index: 8, title: "SSH Agent Hijacking → Linux Host Lateral Movement", computer: "WIN-SOC-LINUX-01", chain_confidence: 0.92, kill_chain_phases: ["lateral-movement"], affected_users: ["WIN-SOC\\DBAdmin"], affected_hosts: ["WIN-SOC-LINUX-01", "WIN-SOC-LINUX-02"], events: ["fnd-ds-009-log-9"] },
    { chain_id: "chain-ds-009-09", chain_index: 9, title: "Audio Capture + Nightly Scheduled Exfiltration", computer: "WIN-SOC-PROD-08", chain_confidence: 0.90, kill_chain_phases: ["collection", "exfiltration"], affected_users: ["WIN-SOC\\User3", "WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-08", "WIN-SOC-PROD-09"], events: ["fnd-ds-009-log-10"] },
    { chain_id: "chain-ds-009-10", chain_index: 10, title: "Windows Service Persistence → Cloud Service Discovery", computer: "WIN-SOC-PROD-10", chain_confidence: 0.88, kill_chain_phases: ["persistence", "discovery"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-10"], events: ["fnd-ds-009-log-11"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user009logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🔴 CRITICAL (95%) |
| Total Logs | 10,000 |
| Threat Events | 200 |
| Attack Chains | 10 |
| Affected Hosts | 11 |
| Affected Users | 13 |

---

## 🧠 2. EXECUTIVE SUMMARY
An **APT-level critical threat campaign** was detected in **user009logs.csv** spanning **10 distinct attack chains** across 12 MITRE ATT&CK tactic categories.

The adversary demonstrated nation-state-level capabilities: DCSync credential replication, **Skeleton Key malware implanted on WIN-SOC-DC-01**, PrintNightmare exploitation (CVE-2021-34527), DPAPI master key theft, Process Doppelganging for anti-forensic evasion, ICMP tunneling C2, and covert nightly exfiltration.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-10**, **WIN-SOC-DC-01**, **WIN-SOC-LINUX-01/02**, **WIN-SOC-VPN-01**

Immediate domain-wide credential rotation, DC rebuild assessment, and full forensic investigation are required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-02 23:45:00 | WIN-SOC-PROD-01 | DNS Reconnaissance — Zone Transfer Attempts |
| 2026-04-02 23:55:00 | WIN-SOC-VPN-01 | VPN Credential Abuse — External Initial Access |
| 2026-04-03 00:05:24 | WIN-SOC-PROD-02 | PowerShell Encoded IEX — Stage 1 Dropper |
| 2026-04-03 00:05:26 | WIN-SOC-DC-01 | DCSync — MS-DRSR Replication from Non-DC Host |
| 2026-04-03 00:08:00 | WIN-SOC-PROD-03 | PrintNightmare Exploit — SYSTEM Escalation |
| 2026-04-03 00:10:00 | WIN-SOC-PROD-02 | Domain Trust + Cloud Service Discovery |
| 2026-04-03 00:15:00 | WIN-SOC-DC-01 | Skeleton Key Malware Implanted in lsass.exe |
| 2026-04-03 00:20:00 | WIN-SOC-PROD-06 | Process Doppelganging — Fileless Evasion |
| 2026-04-03 00:25:00 | WIN-SOC-PROD-05 | DPAPI Master Key Theft — Browser Credentials |
| 2026-04-03 00:30:00 | WIN-SOC-PROD-07 | ICMP Tunneling C2 Established |
| 2026-04-03 00:35:00 | WIN-SOC-LINUX-01 | SSH Agent Hijacking — Linux Lateral Movement |
| 2026-04-03 01:00:00 | WIN-SOC-PROD-08 | Microphone Audio Capture Initiated |
| 2026-04-03 02:00:00 | WIN-SOC-PROD-09 | Nightly Scheduled Exfiltration Beacon |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** DNS Reconnaissance → VPN Credential Abuse → External Initial Access
- **Chain 2:** PowerShell Dropper → Domain Trust Discovery → DCSync Full AD Credential Harvest
- **Chain 3:** PrintNightmare CVE-2021-34527 Exploit → SYSTEM Privilege Escalation
- **Chain 4:** Skeleton Key Malware Implanted on WIN-SOC-DC-01 — Universal Authentication Bypass
- **Chain 5:** Process Doppelganging — NTFS-Transaction Fileless Anti-Forensic Evasion
- **Chain 6:** DPAPI Master Key Theft — Browser + Windows Vault Credential Decryption
- **Chain 7:** ICMP Tunneling Covert C2 — Encrypted Command Channel (8s Beacon)
- **Chain 8:** SSH Agent Hijacking → Linux Host Lateral Movement via ptrace
- **Chain 9:** Audio Capture (Microphone) + Scheduled Nightly Exfiltration Beacon
- **Chain 10:** Windows Service Persistence → Cloud Service Discovery (AWS/Azure)

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1590.002 | Gather Victim Network Information: DNS | Reconnaissance |
| T1133 | External Remote Services (VPN Abuse) | Initial Access |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1543.003 | Windows Service for Persistence | Persistence |
| T1556.001 | Skeleton Key — Modify Authentication Process | Persistence |
| T1068 | PrintNightmare Privilege Escalation | Privilege Escalation |
| T1055.012 | Process Doppelganging | Defense Evasion |
| T1006 | Direct Volume Access (NTFS Transactions) | Defense Evasion |
| T1003.006 | DCSync Replication Attack | Credential Access |
| T1555.003 | DPAPI Credential Store Theft | Credential Access |
| T1526 | Cloud Service Discovery | Discovery |
| T1482 | Domain Trust Discovery | Discovery |
| T1563.001 | SSH Hijacking for Lateral Movement | Lateral Movement |
| T1095 | Non-Application Layer Protocol — ICMP C2 | Command & Control |
| T1123 | Audio Capture | Collection |
| T1029 | Scheduled Transfer — Nightly Exfil Beacon | Exfiltration |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | DCSync AD Replication Credential Harvest | 15 |
| 🔴 CRITICAL | Skeleton Key Domain Controller Implant | 10 |
| 🔴 CRITICAL | PrintNightmare Privilege Escalation | 15 |
| 🔴 CRITICAL | DPAPI Master Key Theft | 10 |
| 🟠 HIGH | VPN Credential Abuse Initial Access | 15 |
| 🟠 HIGH | Process Doppelganging Defense Evasion | 15 |
| 🟠 HIGH | SSH Session Hijacking Lateral Movement | 15 |
| 🟠 HIGH | ICMP Tunneling C2 | 20 |
| 🟡 MEDIUM | DNS Reconnaissance | 20 |
| 🟡 MEDIUM | Domain Trust + Cloud Service Discovery | 30 |
| 🟡 MEDIUM | Audio Capture Collection | 15 |
| 🟡 MEDIUM | Nightly Scheduled Exfil Beacon | 15 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — DNS recon
- WIN-SOC-PROD-02 — PowerShell dropper, domain/cloud discovery, DCSync origin
- WIN-SOC-PROD-03/04 — PrintNightmare SYSTEM escalation
- WIN-SOC-PROD-05 — DPAPI master key theft
- WIN-SOC-PROD-06 — Process Doppelganging evasion
- WIN-SOC-PROD-07 — ICMP C2 tunneling
- WIN-SOC-PROD-08 — Audio capture
- WIN-SOC-PROD-09/10 — Nightly exfil, service persistence
- WIN-SOC-DC-01 — DCSync victim, Skeleton Key implanted
- WIN-SOC-LINUX-01/02 — SSH hijacking targets
- WIN-SOC-VPN-01 — External initial access

**Users**
- WIN-SOC\\Admin, WIN-SOC\\User3, WIN-SOC\\DBAdmin
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Rebuild WIN-SOC-DC-01 immediately** — Skeleton Key means lsass.exe is fully compromised
- **Reset krbtgt password twice** (72h apart) to invalidate all Kerberos tickets
- **Patch PrintNightmare** (CVE-2021-34527) — disable Print Spooler on all servers immediately
- **Revoke and rotate VPN credentials** — DPAPI-derived credentials are fully exposed
- **Block ICMP tunneling** — inspect and limit ICMP payload size at perimeter to 64 bytes
- **Audit SSH agent forwarding** on all Linux hosts and restrict ptrace access
- **Deploy cloud security posture management (CSPM)** to detect unauthorized AWS/Azure access
- **Block microphone access** by unauthorized processes via endpoint DLP
- **Monitor 2 AM UTC traffic** for covert scheduled exfiltration patterns
- **Rotate all 13 affected account credentials** and re-evaluate domain trust relationships

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 95% (CRITICAL)**

| Dimension | Rating |
|-----------|--------|
| Impact | CRITICAL |
| Likelihood | CRITICAL |
| Severity | CRITICAL |
| Confidence | 98% |
`

  const summary: MockSummary = {
    scan_id: "user-009",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A CRITICAL APT-level campaign was detected in user009logs.csv. Analysis identified 200 threat events across 11 hosts and 10 attack chains. Primary vectors: DCSync AD Replication, Skeleton Key DC Implant, PrintNightmare Exploit, DPAPI Credential Theft, Process Doppelganging, ICMP C2 Tunneling, and SSH Hijacking. DC rebuild required. Risk Score: 95% CRITICAL.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A CRITICAL APT-level campaign detected in user009logs.csv spanning 10 attack chains. Techniques: DCSync (T1003.006), Skeleton Key (T1556.001), PrintNightmare (T1068), DPAPI (T1555.003), Process Doppelganging (T1055.012), ICMP C2 (T1095), SSH Hijacking (T1563.001), Audio Capture (T1123). Risk Score: 95% CRITICAL.",
      attack_narrative: "Between 2026-04-02 23:45 UTC and 2026-04-03 02:00 UTC, a nation-state-level threat actor executed a 10-chain campaign. VPN credentials stolen via DPAPI provided initial access. PowerShell droppers were followed by DCSync extraction of all domain hashes. PrintNightmare escalated to SYSTEM on two servers. Skeleton Key malware was implanted into WIN-SOC-DC-01 lsass.exe enabling universal authentication bypass. Process Doppelganging provided fileless anti-forensic evasion. ICMP tunneling provided covert C2. SSH agent hijacking moved laterally to Linux hosts. Audio capture and nightly scheduled transfers silently exfiltrated data.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-10, WIN-SOC-DC-01, WIN-SOC-LINUX-01/02, WIN-SOC-VPN-01\n\n**Users:** WIN-SOC\\Admin, WIN-SOC\\User3, WIN-SOC\\DBAdmin, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Rebuild WIN-SOC-DC-01** — Skeleton Key fully compromises lsass.exe.\n2. **Reset krbtgt password twice** (72h apart) to invalidate all forged tickets.\n3. **Patch PrintNightmare** — disable Print Spooler on all servers immediately.\n4. **Block ICMP tunneling** — limit ICMP payload to 64 bytes at perimeter.\n5. **Revoke VPN credentials** — rotate all credentials reachable by DPAPI.\n6. **Restrict SSH agent forwarding** and disable ptrace on Linux hosts.\n7. **Monitor 2 AM UTC traffic** for nightly exfil patterns.\n8. **Rotate all 13 affected account credentials**.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── USER0010 LOGS JSON DATASET ───────────────────────────────────────────────
// Derived from /datasets/dataset10/user0010logs.json
// Campaign: Multi-Vector APT with UEFI Persistence, NTLM Relay, Steganographic Exfil — 78% HIGH

function buildUser0010Dataset() {
  const analysis: MockAnalysis = {
    scan_id: "user-0010",
    file_name: "user0010logs.csv",
    total_logs: 10000,
    total_threats: 240,
    attack_chain_count: 12,
    risk_score: 7800,
    threat_density: 2.4,
    generated_at: "2026-04-13T10:00:00Z",
    status: "completed",
  }

  const findings: MockFinding[] = [
    { id: "fnd-u0010-01", severity: "critical", title: "UEFI/BIOS Firmware Implant — Persistent Pre-OS Backdoor", detection_type: "yara_match", rule_id: "SOC-T1542-003-0010", mitre_techniques: ["Pre-OS Boot: UEFI/BIOS Firmware Implant"], mitre_ids: ["T1542.003"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01"], count: 10, description: "YARA rule UEFI_IMPLANT_v1 matched a modified UEFI firmware component — an attacker-controlled UEFI module persists below the OS, surviving full disk wipes and OS reinstalls. Immediate hardware-level remediation required.", timestamp: "2026-04-02 00:09:43" },
    { id: "fnd-u0010-02", severity: "critical", title: "NTLM Relay Attack — Forced Authentication Hash Capture", detection_type: "rule", rule_id: "SOC-T1187-0010", mitre_techniques: ["Forced Authentication NTLM Relay"], mitre_ids: ["T1187"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"], count: 15, description: "Responder.py-style NTLM relay detected: attacker poisoned NetBIOS/LLMNR and captured NTLM challenge-response pairs from 2 admin accounts — relayed to authenticate against PROD-03 without cracking the hash.", timestamp: "2026-04-02 00:12:00" },
    { id: "fnd-u0010-03", severity: "critical", title: "Shadow Credentials Kerberos Abuse (KeyCredentialLink)", detection_type: "ml_anomaly", rule_id: "SOC-T1649-0010", mitre_techniques: ["Shadow Credentials: Kerberos Abuse"], mitre_ids: ["T1649"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-DC-01"], count: 15, description: "ML model detected KeyCredentialLink attribute added to a user object (10-sigma anomaly) — shadow credentials technique enabling Kerberos authentication as any domain user without knowing their password.", timestamp: "2026-04-02 00:20:00" },
    { id: "fnd-u0010-04", severity: "high", title: "Token Impersonation — SeImpersonatePrivilege SYSTEM Escalation", detection_type: "behavioral", rule_id: "SOC-T1134-001-0010", mitre_techniques: ["Access Token Manipulation: Token Impersonation"], mitre_ids: ["T1134.001"], affected_users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], count: 20, description: "Behavioral engine flagged token impersonation: a low-privilege process cloned a SYSTEM token via SeImpersonatePrivilege — classic Juicy Potato / PrintSpoofer escalation pattern.", timestamp: "2026-04-02 00:09:43" },
    { id: "fnd-u0010-05", severity: "high", title: "Domain Trust Modification — Cross-Forest Trust Added", detection_type: "behavioral", rule_id: "SOC-T1484-002-0010", mitre_techniques: ["Domain Policy Modification: Trust Modification"], mitre_ids: ["T1484.002"], affected_users: ["WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], count: 15, description: "Behavioral engine detected unauthorized modification of domain trust relationships — a new cross-forest trust was added, enabling lateral movement into a previously isolated forest.", timestamp: "2026-04-02 00:25:00" },
    { id: "fnd-u0010-06", severity: "high", title: "DCOM Lateral Movement — Remote Object Instantiation", detection_type: "rule", rule_id: "SOC-T1021-003-0010", mitre_techniques: ["Distributed Component Object Model (DCOM) Lateral Movement"], mitre_ids: ["T1021.003"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-04", "WIN-SOC-PROD-05"], count: 15, description: "DCOM objects (ShellWindows, MMC20, Excel) instantiated remotely for lateral code execution — a stealthy lateral movement technique that leverages legitimate COM infrastructure.", timestamp: "2026-04-02 00:35:00" },
    { id: "fnd-u0010-07", severity: "high", title: "Remote Email Collection via Exchange Web Services (EWS)", detection_type: "ml_anomaly", rule_id: "SOC-T1114-002-0010", mitre_techniques: ["Email Collection: Remote Email Collection via EWS"], mitre_ids: ["T1114.002"], affected_users: ["WIN-SOC\\SvcMail", "WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-MAIL-01"], count: 20, description: "ML model detected bulk EWS API calls harvesting emails from executive mailboxes — 8.9-sigma anomaly in API call volume. Over 15,000 emails accessed and exfiltrated from C-suite accounts.", timestamp: "2026-04-02 01:00:00" },
    { id: "fnd-u0010-08", severity: "medium", title: "Spearphishing via Teams/Slack — Malicious Link Delivery", detection_type: "yara_match", rule_id: "SOC-T1566-003-0010", mitre_techniques: ["Spearphishing via Service (Teams/Slack)"], mitre_ids: ["T1566.003"], affected_users: ["WIN-SOC\\User2", "WIN-SOC\\User4"], affected_hosts: ["WIN-SOC-PROD-06"], count: 20, description: "YARA rule PHISH_TEAMS_LINK_v2 matched malicious URLs delivered via Microsoft Teams DMs — link redirected through a compromised CDN to a credential harvesting page impersonating an internal HR portal.", timestamp: "2026-04-02 00:05:00" },
    { id: "fnd-u0010-09", severity: "medium", title: "Memory-Only Reflective Code Loading — Fileless Malware", detection_type: "behavioral", rule_id: "SOC-T1620-0010", mitre_techniques: ["Reflective Code Loading (Memory-Only Fileless Malware)"], mitre_ids: ["T1620"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-07"], count: 20, description: "Behavioral engine detected reflective DLL loading: malicious shellcode injected directly into memory without touching disk — a fileless malware technique bypassing file-based AV scanning entirely.", timestamp: "2026-04-02 00:40:00" },
    { id: "fnd-u0010-10", severity: "medium", title: "System Firewall Rules Modified — C2 Port Opened", detection_type: "rule", rule_id: "SOC-T1562-004-0010", mitre_techniques: ["Disable or Modify System Firewall"], mitre_ids: ["T1562.004"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-08"], count: 15, description: "netsh.exe added inbound firewall rules for TCP ports 4443 and 8443 — opening covert C2 listener ports while disabling logging for the new rules to prevent detection.", timestamp: "2026-04-02 00:45:00" },
    { id: "fnd-u0010-11", severity: "medium", title: "Bidirectional Web Services C2 — GitHub/Dropbox Abuse", detection_type: "ml_anomaly", rule_id: "SOC-T1102-002-0010", mitre_techniques: ["Bidirectional C2 via Web Services"], mitre_ids: ["T1102.002"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-09"], count: 20, description: "ML model detected C2 commands issued via GitHub gist comments and Dropbox file polling — legitimate web service abuse blending C2 traffic with normal developer activity.", timestamp: "2026-04-02 00:55:00" },
    { id: "fnd-u0010-12", severity: "medium", title: "Steganographic Payload — Data Hidden in Image Files", detection_type: "ml_anomaly", rule_id: "SOC-T1027-003-0010", mitre_techniques: ["Steganographic Payload Embedding"], mitre_ids: ["T1027.003"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-10"], count: 15, description: "ML model detected anomalous LSB (Least Significant Bit) patterns in PNG files uploaded to an external image hosting service — steganographic data exfiltration hiding sensitive data inside ordinary images.", timestamp: "2026-04-02 01:15:00" },
    { id: "fnd-u0010-13", severity: "low", title: "Spearphishing Credential Harvest — Fake Login Portal", detection_type: "heuristic", rule_id: "SOC-T1598-003-0010", mitre_techniques: ["Spearphishing Link for Credential Harvest"], mitre_ids: ["T1598.003"], affected_users: ["WIN-SOC\\User2", "WIN-SOC\\User5"], affected_hosts: ["WIN-SOC-PROD-06"], count: 20, description: "Heuristic engine identified 2 users visiting a look-alike domain and submitting credentials to a fake Microsoft 365 login portal — credential harvesting preceding the main campaign.", timestamp: "2026-04-01 22:00:00" },
    { id: "fnd-u0010-14", severity: "low", title: "Cryptomining Resource Hijacking — XMRig Detected", detection_type: "yara_match", rule_id: "SOC-T1496-0010", mitre_techniques: ["Resource Hijacking (Cryptomining)"], mitre_ids: ["T1496"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-11"], count: 20, description: "YARA rule XMRIG_MINER_v7 matched a hidden XMRig cryptominer — CPU sustained at 85-90% on PROD-11 generating Monero for the attacker using compromised compute resources.", timestamp: "2026-04-02 00:30:00" },
  ]

  const chains: MockChain[] = [
    { chain_id: "chain-ds-0010-01", chain_index: 1, title: "Credential Harvest Phishing → Teams/Slack Spearphishing", computer: "WIN-SOC-PROD-06", chain_confidence: 0.88, kill_chain_phases: ["reconnaissance", "initial-access"], affected_users: ["WIN-SOC\\User2", "WIN-SOC\\User4", "WIN-SOC\\User5"], affected_hosts: ["WIN-SOC-PROD-06"], events: ["fnd-ds-0010-log-1"] },
    { chain_id: "chain-ds-0010-02", chain_index: 2, title: "VBScript Execution → Token Impersonation → SYSTEM Escalation", computer: "WIN-SOC-PROD-01", chain_confidence: 0.93, kill_chain_phases: ["execution", "privilege-escalation"], affected_users: ["WIN-SOC\\User1", "NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01", "WIN-SOC-PROD-02"], events: ["fnd-ds-0010-log-2", "fnd-ds-0010-log-3"] },
    { chain_id: "chain-ds-0010-03", chain_index: 3, title: "UEFI Firmware Implant — Pre-OS Persistent Backdoor", computer: "WIN-SOC-PROD-01", chain_confidence: 0.97, kill_chain_phases: ["persistence"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-01"], events: ["fnd-ds-0010-log-4"] },
    { chain_id: "chain-ds-0010-04", chain_index: 4, title: "NTLM Relay Attack → Forced Authentication Hash Capture", computer: "WIN-SOC-PROD-02", chain_confidence: 0.95, kill_chain_phases: ["credential-access", "lateral-movement"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\User1"], affected_hosts: ["WIN-SOC-PROD-02", "WIN-SOC-PROD-03"], events: ["fnd-ds-0010-log-5"] },
    { chain_id: "chain-ds-0010-05", chain_index: 5, title: "Shadow Credentials KeyCredentialLink → Domain Trust Modification", computer: "WIN-SOC-DC-01", chain_confidence: 0.98, kill_chain_phases: ["credential-access", "privilege-escalation"], affected_users: ["WIN-SOC\\Admin", "WIN-SOC\\DomainAdmin"], affected_hosts: ["WIN-SOC-DC-01"], events: ["fnd-ds-0010-log-6"] },
    { chain_id: "chain-ds-0010-06", chain_index: 6, title: "System Firewall Modified → Reflective Code Loading", computer: "WIN-SOC-PROD-07", chain_confidence: 0.91, kill_chain_phases: ["defense-evasion"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-07", "WIN-SOC-PROD-08"], events: ["fnd-ds-0010-log-7"] },
    { chain_id: "chain-ds-0010-07", chain_index: 7, title: "DCOM Lateral Movement → Remote Code Execution", computer: "WIN-SOC-PROD-04", chain_confidence: 0.90, kill_chain_phases: ["lateral-movement"], affected_users: ["WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-PROD-04", "WIN-SOC-PROD-05"], events: ["fnd-ds-0010-log-8"] },
    { chain_id: "chain-ds-0010-08", chain_index: 8, title: "GitHub/Dropbox Web Services C2", computer: "WIN-SOC-PROD-09", chain_confidence: 0.89, kill_chain_phases: ["command-and-control"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-09"], events: ["fnd-ds-0010-log-9"] },
    { chain_id: "chain-ds-0010-09", chain_index: 9, title: "Remote EWS Email Collection — C-Suite Mailbox Exfiltration", computer: "WIN-SOC-MAIL-01", chain_confidence: 0.96, kill_chain_phases: ["collection"], affected_users: ["WIN-SOC\\SvcMail", "WIN-SOC\\Admin"], affected_hosts: ["WIN-SOC-MAIL-01"], events: ["fnd-ds-0010-log-10"] },
    { chain_id: "chain-ds-0010-10", chain_index: 10, title: "Steganographic Exfiltration — Data Hidden in PNG Images", computer: "WIN-SOC-PROD-10", chain_confidence: 0.92, kill_chain_phases: ["exfiltration"], affected_users: ["WIN-SOC\\Dev-01"], affected_hosts: ["WIN-SOC-PROD-10"], events: ["fnd-ds-0010-log-11"] },
    { chain_id: "chain-ds-0010-11", chain_index: 11, title: "XMRig Cryptominer — Resource Hijacking", computer: "WIN-SOC-PROD-11", chain_confidence: 0.87, kill_chain_phases: ["impact"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-11"], events: ["fnd-ds-0010-log-12"] },
    { chain_id: "chain-ds-0010-12", chain_index: 12, title: "UEFI Implant Survives Reimage — Pre-OS Persistence", computer: "WIN-SOC-PROD-12", chain_confidence: 0.94, kill_chain_phases: ["persistence"], affected_users: ["NT AUTHORITY\\SYSTEM"], affected_hosts: ["WIN-SOC-PROD-12"], events: ["fnd-ds-0010-log-13"] },
  ]

  const aiReport = `
# 🔐 AI FORENSIC ANALYSIS REPORT

---

## 📌 1. REPORT METADATA
| Field | Value |
|-------|-------|
| Dataset | user0010logs.csv |
| Generated On | 2026-04-13 10:00:00 UTC |
| Risk Level | 🟠 HIGH (78%) |
| Total Logs | 10,000 |
| Threat Events | 240 |
| Attack Chains | 12 |
| Affected Hosts | 13 |
| Affected Users | 15 |

---

## 🧠 2. EXECUTIVE SUMMARY
A **broad high-severity multi-vector APT campaign** was detected in **user0010logs.csv** spanning **12 distinct attack chains** covering the full MITRE ATT&CK kill chain across 14 tactic categories.

The adversary demonstrated diverse and sophisticated capabilities: **UEFI firmware implant** (survives disk wipes), token impersonation, NTLM relay attacks, Shadow Credentials Kerberos abuse, domain trust modification, DCOM lateral movement, memory-only reflective code loading, remote email collection (C-suite mailboxes), **steganographic data exfiltration**, and cryptomining for resource abuse.

Attack observed across:
- **WIN-SOC-PROD-01** through **WIN-SOC-PROD-12**, **WIN-SOC-DC-01**, **WIN-SOC-MAIL-01**

Immediate containment, full endpoint forensics, hardware-level UEFI inspection, and domain-wide review are required.

---

## ⏱️ 3. ATTACK TIMELINE
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
| 2026-04-01 22:00:00 | WIN-SOC-PROD-06 | Spearphishing Credential Harvest — Fake M365 Portal |
| 2026-04-02 00:05:00 | WIN-SOC-PROD-06 | Teams/Slack Spearphishing — Malicious Link Delivered |
| 2026-04-02 00:09:41 | WIN-SOC-PROD-01 | PowerShell IEX + VBScript Execution |
| 2026-04-02 00:09:43 | WIN-SOC-PROD-01 | Token Impersonation → SYSTEM Escalation |
| 2026-04-02 00:09:43 | WIN-SOC-PROD-01 | UEFI Firmware Implant Written |
| 2026-04-02 00:12:00 | WIN-SOC-PROD-02 | NTLM Relay Attack — Hash Capture + Relay |
| 2026-04-02 00:20:00 | WIN-SOC-DC-01 | Shadow Credentials KeyCredentialLink Added |
| 2026-04-02 00:25:00 | WIN-SOC-DC-01 | Domain Trust Modified — Cross-Forest Trust Added |
| 2026-04-02 00:30:00 | WIN-SOC-PROD-11 | XMRig Cryptominer Installed |
| 2026-04-02 00:35:00 | WIN-SOC-PROD-04 | DCOM Lateral Movement Initiated |
| 2026-04-02 00:40:00 | WIN-SOC-PROD-07 | Reflective Memory-Only Code Loading |
| 2026-04-02 00:45:00 | WIN-SOC-PROD-08 | Firewall Rules Modified — C2 Ports Opened |
| 2026-04-02 00:55:00 | WIN-SOC-PROD-09 | GitHub/Dropbox C2 — Web Services Abuse |
| 2026-04-02 01:00:00 | WIN-SOC-MAIL-01 | EWS Remote Email Collection — C-Suite Mailboxes |
| 2026-04-02 01:15:00 | WIN-SOC-PROD-10 | Steganographic PNG Image Exfiltration |

---

## 🧩 4. ATTACK CHAINS OVERVIEW
- **Chain 1:** Credential Harvest Phishing → Teams/Slack Spearphishing → Initial Access
- **Chain 2:** VBScript Execution → Token Impersonation → SeImpersonatePrivilege SYSTEM Escalation
- **Chain 3:** UEFI/BIOS Firmware Implant — Pre-OS Persistent Backdoor (Survives Disk Wipe)
- **Chain 4:** NTLM Relay (Responder) → Forced Authentication → Relay to PROD-03
- **Chain 5:** Shadow Credentials (KeyCredentialLink) → Domain Trust Modification (Cross-Forest)
- **Chain 6:** Firewall Rules Disabled → Reflective Memory-Only Code Loading (Fileless)
- **Chain 7:** DCOM Object Remote Instantiation → Lateral Code Execution
- **Chain 8:** GitHub Gist + Dropbox Polling — Bidirectional Web Services C2
- **Chain 9:** EWS API Remote Email Collection — 15,000 C-Suite Emails Exfiltrated
- **Chain 10:** Steganographic LSB Embedding — Data Hidden in PNG Files Uploaded
- **Chain 11:** XMRig Cryptominer — CPU/Resource Hijacking on PROD-11
- **Chain 12:** UEFI Implant Persists Through Reimage on PROD-12

---

## 🎯 5. MITRE ATT&CK MAPPING
| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1598.003 | Spearphishing Link for Credential Harvest | Reconnaissance |
| T1608.001 | Stage Capabilities: Upload Malware | Resource Development |
| T1566.003 | Spearphishing via Service (Teams/Slack) | Initial Access |
| T1059.005 | Visual Basic Script Execution | Execution |
| T1059.001 | PowerShell Encoded Command Execution | Execution |
| T1542.003 | UEFI/BIOS Firmware Implant | Persistence |
| T1098.001 | Shadow Credentials: Account Manipulation | Persistence |
| T1134.001 | Token Impersonation / Privilege Escalation | Privilege Escalation |
| T1484.002 | Domain Policy Modification: Trust Modification | Privilege Escalation |
| T1562.004 | Disable or Modify System Firewall | Defense Evasion |
| T1620 | Reflective Code Loading (Memory-Only) | Defense Evasion |
| T1187 | Forced Authentication NTLM Relay | Credential Access |
| T1649 | Shadow Credentials Kerberos Abuse | Credential Access |
| T1018 | Remote System Discovery | Discovery |
| T1021.003 | Distributed Component Object Model (DCOM) | Lateral Movement |
| T1102.002 | Bidirectional C2 via Web Services | Command & Control |
| T1114.002 | Remote Email Collection via EWS | Collection |
| T1027.003 | Steganographic Payload Embedding | Exfiltration |
| T1496 | Resource Hijacking (Cryptomining) | Impact |

---

## 🚨 6. FINDINGS SUMMARY
| Severity | Finding | Count |
|----------|---------|-------|
| 🔴 CRITICAL | UEFI Firmware Implant Persistence | 10 |
| 🔴 CRITICAL | NTLM Relay Attack | 15 |
| 🔴 CRITICAL | Shadow Credentials Kerberos Abuse | 15 |
| 🟠 HIGH | Token Impersonation Privilege Escalation | 20 |
| 🟠 HIGH | Domain Trust Modification | 15 |
| 🟠 HIGH | DCOM Lateral Movement | 15 |
| 🟠 HIGH | Remote Email Collection via EWS | 20 |
| 🟡 MEDIUM | Phishing via Teams/Slack | 20 |
| 🟡 MEDIUM | Memory-Only Reflective Code Loading | 20 |
| 🟡 MEDIUM | Firewall Rules Modified | 15 |
| 🟡 MEDIUM | Bidirectional Web Services C2 | 20 |
| 🟡 MEDIUM | Steganographic Data Exfiltration | 15 |
| 🔵 LOW | Spearphishing Credential Harvest | 20 |
| 🔵 LOW | Cryptomining Resource Hijacking | 20 |

---

## 🖥️ 7. AFFECTED ENTITIES
**Hosts**
- WIN-SOC-PROD-01 — UEFI implant, token impersonation, PowerShell dropper
- WIN-SOC-PROD-02 — NTLM relay origin
- WIN-SOC-PROD-03 — NTLM relay target
- WIN-SOC-PROD-04/05 — DCOM lateral movement
- WIN-SOC-PROD-06 — Phishing victim host
- WIN-SOC-PROD-07 — Reflective code loading
- WIN-SOC-PROD-08 — Firewall modified, C2 ports opened
- WIN-SOC-PROD-09 — GitHub/Dropbox C2
- WIN-SOC-PROD-10 — Steganographic exfiltration
- WIN-SOC-PROD-11 — Cryptomining (XMRig)
- WIN-SOC-PROD-12 — UEFI implant (second host)
- WIN-SOC-DC-01 — Shadow credentials, domain trust modification
- WIN-SOC-MAIL-01 — EWS email exfiltration

**Users**
- WIN-SOC\\Admin, WIN-SOC\\DomainAdmin
- WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\User4, WIN-SOC\\User5
- WIN-SOC\\Dev-01, WIN-SOC\\SvcMail
- NT AUTHORITY\\SYSTEM

---

## 🛡️ 8. RECOMMENDATIONS
- **Perform UEFI firmware inspection** on PROD-01 and PROD-12 — hardware-level remediation may be required (reflash or hardware replacement)
- **Block LLMNR and NetBIOS** domain-wide via GPO to prevent NTLM relay attacks
- **Audit KeyCredentialLink attributes** on all AD objects and remove unauthorized shadow credentials
- **Revert domain trust modifications** and audit all inter-forest trust relationships
- **Block GitHub, Dropbox, and image hosting** at proxy/firewall to disrupt web service C2
- **Audit Exchange/EWS API access logs** and revoke delegated mailbox permissions
- **Scan PNG/image uploads** at DLP gateway for steganographic LSB anomalies
- **Remove XMRig and recover CPU resources** on WIN-SOC-PROD-11
- **Enable WDAC/AppLocker** to prevent VBScript and reflective DLL loading
- **Rotate all 15 affected account credentials** and re-evaluate privileged access

---

## 📊 9. RISK ASSESSMENT
**Overall Risk Score: 78% (HIGH)**

| Dimension | Rating |
|-----------|--------|
| Impact | HIGH |
| Likelihood | HIGH |
| Severity | HIGH |
| Confidence | 94% |
`

  const summary: MockSummary = {
    scan_id: "user-0010",
    generated_at: "2026-04-13T10:00:00Z",
    executive_briefing: "A HIGH-severity multi-vector APT campaign was detected in user0010logs.csv. Analysis identified 240 threat events across 13 hosts and 12 attack chains. Primary vectors: UEFI Firmware Implant, NTLM Relay, Shadow Credentials, DCOM Lateral Movement, Remote EWS Email Collection, Steganographic Exfiltration, and Cryptomining. Risk Score: 78% HIGH.",
    content_markdown: aiReport,
    ai_summary_report: aiReport,
    model: "Gemini-2.5-Pro",
    sections: {
      executive_summary: "A HIGH-severity multi-vector APT campaign detected in user0010logs.csv spanning 12 attack chains. Techniques: UEFI Implant (T1542.003), NTLM Relay (T1187), Shadow Credentials (T1649), Token Impersonation (T1134.001), DCOM Lateral Movement (T1021.003), EWS Email Collection (T1114.002), Steganographic Exfil (T1027.003), Cryptomining (T1496). Risk Score: 78% HIGH.",
      attack_narrative: "Between 2026-04-01 22:00 UTC and 2026-04-02 01:15 UTC, a sophisticated threat actor executed a 12-chain campaign spanning the full kill chain. Credential harvesting via fake M365 portal and Teams/Slack phishing provided initial access. VBScript and PowerShell droppers executed token impersonation escalating to SYSTEM. A UEFI firmware implant was written, persisting below the OS. NTLM relay captured admin hashes for lateral movement. Shadow credentials were added to AD accounts for persistent Kerberos access. Domain trust was modified to enable cross-forest lateral expansion. DCOM objects laterally executed code. A GitHub/Dropbox C2 blended with developer traffic. EWS API collected 15,000 C-suite emails. Data was exfiltrated via PNG steganography. XMRig cryptominer hijacked resources on PROD-11.",
      affected_assets: "**Hosts:** WIN-SOC-PROD-01 through WIN-SOC-PROD-12, WIN-SOC-DC-01, WIN-SOC-MAIL-01\n\n**Users:** WIN-SOC\\Admin, WIN-SOC\\DomainAdmin, WIN-SOC\\User1, WIN-SOC\\User2, WIN-SOC\\User4, WIN-SOC\\User5, WIN-SOC\\Dev-01, WIN-SOC\\SvcMail, NT AUTHORITY\\SYSTEM",
      remediation_steps: "1. **Inspect and reflash UEFI firmware** on PROD-01 and PROD-12 (or replace hardware).\n2. **Block LLMNR and NetBIOS** via GPO to prevent NTLM relay.\n3. **Audit and remove KeyCredentialLink** shadow credentials from all AD objects.\n4. **Revert domain trust modifications** and audit inter-forest trust relationships.\n5. **Block GitHub, Dropbox, and image hosting** at proxy/firewall.\n6. **Audit EWS API access** and revoke unauthorized mailbox delegations.\n7. **Enable DLP image scanning** to detect LSB steganographic patterns.\n8. **Rotate all 15 affected account credentials** and implement LAPS.",
    },
  }

  return { analysis, events: [], findings, chains, summary }
}

// ─── BUILD ALL MOCK DATA ──────────────────────────────────────────────────────

const USER_UPLOAD_DATASET = buildUserUploadDataset()
const USER_001_DATASET = buildUser001Dataset()
const USER_002_DATASET = buildUser002Dataset()
const USER_003_DATASET = buildUser003Dataset()
const USER_004_DATASET = buildUser004Dataset()
const USER_005_DATASET = buildUser005Dataset()
const USER_006_DATASET = buildUser006Dataset()
const USER_007_DATASET = buildUser007Dataset()
const USER_008_DATASET = buildUser008Dataset()
const USER_009_DATASET = buildUser009Dataset()
const USER_0010_DATASET = buildUser0010Dataset()
export const MOCK_DATASETS = [
  ...DATASET_META.map(buildMockDataset),
  USER_UPLOAD_DATASET,
  USER_001_DATASET,
  USER_002_DATASET,
  USER_003_DATASET,
  USER_004_DATASET,
  USER_005_DATASET,
  USER_006_DATASET,
  USER_007_DATASET,
  USER_008_DATASET,
  USER_009_DATASET,
  USER_0010_DATASET,
]

// ─── LOOKUP HELPERS ───────────────────────────────────────────────────────────

// Scan IDs that belong to user-uploaded datasets — excluded from the pre-loaded list
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
