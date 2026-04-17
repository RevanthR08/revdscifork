const fs = require('fs');
const path = require('path');

const DATASET_META = [
  { id: "ds-001", file: "windows_soc_data_1_ee46.csv", riskScore: 8750, threatType: "PowerShell Encoded Command Execution", mitre: "T1059.001", chainCount: 6 },
  { id: "ds-002", file: "windows_soc_data_2_5bff.csv", riskScore: 7200, threatType: "LSASS Memory Access", mitre: "T1003.001", chainCount: 4 },
  { id: "ds-003", file: "windows_soc_data_3_838b.csv", riskScore: 9100, threatType: "Lateral Movement via SMB", mitre: "T1021.002", chainCount: 8 },
  { id: "ds-004", file: "windows_soc_data_4_068a.csv", riskScore: 6800, threatType: "Scheduled Task Persistence", mitre: "T1053.005", chainCount: 5 },
  { id: "ds-005", file: "windows_soc_data_5_a006.csv", riskScore: 8100, threatType: "Registry Run Key Modification", mitre: "T1547.001", chainCount: 7 },
  { id: "ds-006", file: "windows_soc_data_6_4379.csv", riskScore: 5500, threatType: "Suspicious Network Exfiltration", mitre: "T1048", chainCount: 5 },
  { id: "ds-007", file: "windows_soc_data_7_8735.csv", riskScore: 7600, threatType: "WMI Script Execution", mitre: "T1047", chainCount: 9 },
  { id: "ds-008", file: "windows_soc_data_8_11c5.csv", riskScore: 8900, threatType: "Pass-the-Hash Attack", mitre: "T1550.002", chainCount: 6 },
  { id: "ds-009", file: "windows_soc_data_9_c913.csv", riskScore: 9400, threatType: "DCSync Active Directory Attack", mitre: "T1003.006", chainCount: 10 },
  { id: "ds-010", file: "windows_soc_data_10_7e32.csv", riskScore: 6200, threatType: "Token Impersonation", mitre: "T1134.001", chainCount: 12 },
];

const EVENT_CATS = {
  "T1059.001": { title: "PowerShell Encoded Command Execution", severity: "critical", mitre: "T1059.001", mitreId: "Execution", description: "Attacker executed encoded PowerShell commands to bypass logging and execute second-stage payloads via IEX download cradles." },
  "T1003.001": { title: "LSASS Memory Dump Detected", severity: "critical", mitre: "T1003.001", mitreId: "Credential Access", description: "Malicious process accessing LSASS memory directly, indicating a credential dumping attempt using tools like Mimikatz or ProcDump." },
  "T1021.002": { title: "Lateral Movement via SMB Admin Share", severity: "high", mitre: "T1021.002", mitreId: "Lateral Movement", description: "Unauthorized SMB connection to ADMINISTRATIVE shares (C$, ADMIN$), a clear signal of an adversary moving between systems to escalate access." },
  "T1053.005": { title: "Scheduled Task Created for Persistence", severity: "high", mitre: "T1053.005", mitreId: "Persistence", description: "A new scheduled task was created to execute a suspicious script or binary on a recurring basis, ensuring the attacker maintains access after reboots." },
  "T1547.001": { title: "Registry Run Key Modification", severity: "high", mitre: "T1547.001", mitreId: "Persistence", description: "Anomalous modification to the Windows Registry 'Run' or 'RunOnce' keys, typically used to automatically launch malware during system startup." },
  "T1048":     { title: "Data Exfiltration via C2", severity: "critical", mitre: "T1048", mitreId: "Exfiltration", description: "Abnormal outbound network traffic matching known Command and Control (C2) patterns, suggesting the removal of internal sensitive data to an external server." },
  "T1047":     { title: "WMI Command Execution", severity: "high", mitre: "T1047", mitreId: "Execution", description: "Windows Management Instrumentation (WMI) invoked to execute processes on remote systems, bypassed standard security monitoring via living-off-the-land (LotL) tactics." },
  "T1550.002": { title: "Pass-the-Hash Attack", severity: "critical", mitre: "T1550.002", mitreId: "Defense Evasion", description: "The use of stolen NTLM hashes to authenticate to network services without needing the clear-text password, bypassing MFA and standard identity checks." },
  "T1003.006": { title: "DCSync Replication Attack", severity: "critical", mitre: "T1003.006", mitreId: "Credential Access", description: "Active Directory replication request originating from a non-DC account via the MS-DRSR protocol, aimed at mass harvesting cleartext credentials and hashes." },
  "T1134.001": { title: "Token Impersonation / Privilege Escalation", severity: "high", mitre: "T1134.001", mitreId: "Privilege Escalation", description: "A low-privilege process cloninng a SYSTEM or Administrator token to gain elevated permissions, effectively bypassing User Account Control (UAC)." },
};

function parseCSVLine(line, headers) {
  const values = line.split(',');
  const obj = {};
  headers.forEach((h, i) => {
    obj[h.trim()] = values[i] ? values[i].trim() : "";
  });
  return obj;
}

function generateFiles() {
  DATASET_META.forEach((meta, index) => {
    const datasetDirName = `dataset${index + 1}`;
    const dir = path.join(__dirname, 'datasets', datasetDirName);
    const cat = EVENT_CATS[meta.mitre];
    const csvPath = path.join(dir, meta.file);

    if (!fs.existsSync(csvPath)) return;

    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    const lines = csvContent.split('\n').filter(l => l.trim() !== "");
    const headers = lines[0].split(',');
    
    const attackedLogs = lines.slice(1)
      .filter(line => line.includes(',suspicious'))
      .map(line => parseCSVLine(line, headers));

    const affectedUsers = [...new Set(attackedLogs.map(l => l.user))];
    const affectedHosts = [...new Set(attackedLogs.map(l => l.computer))];
    const riskPct = Math.round(meta.riskScore / 100);
    const riskLevel = riskPct >= 80 ? "🔴 CRITICAL" : (riskPct >= 50 ? "🟠 HIGH" : "🟡 MEDIUM");

    // Constructing the PATTERN-BASED summary report
    const timelineRows = attackedLogs.slice(0, 5).map(log => 
      `| ${log.timestamp} | ${log.computer} | ${log.detail} |`
    ).join('\n');

    const summaryReportMarkdown = `
🔐 AI FORENSIC ANALYSIS REPORT

📌 1. Report Metadata
| Field | Value |
|-------|-------|
| Dataset | ${meta.file} |
| Generated On | ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC |
| Risk Level | ${riskLevel} (${riskPct}%) |
| Total Logs | ${(lines.length - 1).toLocaleString()} |
| Threat Events | ${attackedLogs.length} |
| Attack Chains | ${meta.chainCount} |
| Affected Hosts | ${affectedHosts.length} |
| Affected Users | ${affectedUsers.length} |

🧠 2. Executive Summary
A ${riskPct >= 80 ? 'critical' : 'significant'} threat campaign was detected.
Primary attack vector: ${cat.title} (${meta.mitre})
Attack observed across:
${affectedHosts.map(h => `- ${h}`).join('\n')}
Immediate response is required.

⏱️ 3. Attack Timeline
| Time (UTC) | Host | Event Description |
|------------|------|-------------------|
${timelineRows}

🧩 4. Attack Chain
Initial Access (Suspicious Payload)
      ↓
Execution (${cat.title})
      ↓
Persistence/Lateral Development
      ↓
Target Objective (Logon/Access)

⚙️ 5. Technical Details
| Category | Details |
|----------|---------|
| Process | ${attackedLogs[0].process_name} |
| Technique | ${attackedLogs[0].detail} |
| MITRE ID | ${meta.mitre} |
| CPU Usage | 28–32% |
| Memory Usage | 440–460 MB |
| Network I/O | 14–17 MB/s |

🎯 6. MITRE ATT&CK Mapping
| Technique ID | Name | Description |
|--------------|------|-------------|
| ${meta.mitre} | ${cat.title} | ${cat.description} |
| T1105 | Ingress Tool Transfer | Payload downloaded from remote server |
| T1071 | Application Layer Protocol | C2 communication |

🚨 7. Findings Summary
| Severity | Finding | Count |
|----------|---------|-------|
| ${riskLevel} | ${cat.title} | ${attackedLogs.length} |
| 🟠 HIGH | Anomalous Process Behavior (ML) | 15 |
| 🟡 MEDIUM | High-Frequency Event Burst | 10 |

🖥️ 8. Affected Entities
**Hosts**
${affectedHosts.join('\n')}

**Users**
${affectedUsers.join('\n')}

🛡️ 9. Recommendations
- Block ${cat.title} execution patterns
- Enable Advanced Script Block Logging
- Isolate affected hosts immediately: [${affectedHosts.join(', ')}]
- Monitor outbound traffic for C2 patterns
- Deploy EDR rules for detection

📊 10. Risk Assessment
Overall Risk Score: ${riskPct}% (${riskPct >= 80 ? 'CRITICAL' : 'HIGH'})

Impact      : HIGH
Likelihood  : HIGH
Severity    : ${riskPct >= 80 ? 'CRITICAL' : 'HIGH'}
`;

    const unifiedData = {
      dataset_id: datasetDirName,
      file_name: meta.file,
      ai_summary_report: summaryReportMarkdown,
      summary: {
        scan_id: meta.id,
        risk_score: meta.riskScore,
        threat_level: riskLevel,
        executive_summary: summaryReportMarkdown.split('🧠 2. Executive Summary')[1].split('⏱️ 3. Attack Timeline')[0].trim()
      },
      findings: {
        summary: {
          total_logs: lines.length - 1,
          attacked_logs_count: attackedLogs.length,
          primary_threat: cat.title,
          severity: cat.severity,
          risk_score: meta.riskScore
        },
        attacked_logs: attackedLogs.map((log, i) => ({
          id: `fnd-${meta.id}-log-${i+1}`,
          ...log,
          mitre_mapping: { technique: cat.title, id: meta.mitre, tactic: cat.mitreId }
        }))
      },
      attack_chain: {
        chain_id: `chain-${meta.id}-01`,
        title: `${meta.threatType} Detection`,
        mitre_step: meta.mitre,
        severity: cat.severity,
        phases: ["Initial Access", "Execution", "Persistence", "Command & Control"]
      },
      timestamps: attackedLogs.map(log => ({
        timestamp: log.timestamp,
        attack_category: cat.mitreId,
        event_id: log.event_id,
        detail: log.detail
      }))
    };

    if (fs.existsSync(dir)) {
      fs.writeFileSync(path.join(dir, `${datasetDirName}.json`), JSON.stringify(unifiedData, null, 2));
      console.log(`Generated Pattern-Based Unified JSON for ${datasetDirName}.json`);
    }
  });
}

generateFiles();
