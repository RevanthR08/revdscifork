// =============================================================================
// MOCK DATA — Derived from 10 Windows SOC Event Log CSV Datasets
// All 10 datasets share the same schema:
//   timestamp, event_id, level, source, computer, user, opcode,
//   task_category, process_id, process_name, detail, cpu_usage,
//   mem_usage, network_io, integrity_level, is_signed, label
//
// Each dataset: 10,000 rows | 9,970 normal | 30 suspicious
// Threat events: powershell.exe "Encoded IEX Download", event_id 4688
// =============================================================================

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
  detection_type: "rule" | "ml_anomaly" | "impossible_travel"
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

// ─── BUILD ALL MOCK DATA ──────────────────────────────────────────────────────

const USER_UPLOAD_DATASET = buildUserUploadDataset()
export const MOCK_DATASETS = [...DATASET_META.map(buildMockDataset), USER_UPLOAD_DATASET]

// ─── LOOKUP HELPERS ───────────────────────────────────────────────────────────

export function getMockAnalysisList(): MockAnalysis[] {
  return MOCK_DATASETS.map(d => d.analysis)
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
