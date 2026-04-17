"""
Windows SOC Event Log Dataset Generator
========================================
Generates realistic-looking Windows Security/Sysmon event logs
in the same CSV format as the existing datasets, WITHOUT a label column.

Usage:
    python generate_dataset.py                    -> Generates 10k rows (default)
    python generate_dataset.py 50000              -> Generates 50k rows
    python generate_dataset.py 100000 my_logs.csv -> 100k rows, custom filename
    python generate_dataset.py 10000 25000 50000  -> Multiple sizes at once
"""

import csv
import random
import sys
import os
from datetime import datetime, timedelta

# ─── CONFIGURATION ─────────────────────────────────────────────────────────────

COMPUTERS = [
    "WIN-SOC-PROD-01",
    "WIN-SOC-PROD-02",
    "WIN-SOC-PROD-03",
    "WIN-SOC-DEV-01",
    "WIN-SOC-DC-01",
]

USERS = [
    "WIN-SOC\\Admin",
    "WIN-SOC\\User1",
    "WIN-SOC\\Dev-01",
    "WIN-SOC\\SvcAcct",
    "WIN-SOC\\Analyst",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\NETWORK SERVICE",
]

INTEGRITY_LEVELS = ["Low", "Medium", "High", "System"]

# ─── EVENT DEFINITIONS ─────────────────────────────────────────────────────────
# Each event type maps to a realistic Windows log entry.
# (event_id, level, source, opcode, task_category, process_name, detail, is_signed_weight)
# is_signed_weight: probability of is_signed=1 (0.0-1.0)

NORMAL_EVENTS = [
    # Logon events
    (4624, "Information", "Security", "Logon",    "Logon",          "explorer.exe",   "System Check",              1.0),
    (4624, "Information", "Security", "Logon",    "Logon",          "services.exe",   "System Check",              1.0),
    (4624, "Information", "Security", "Logon",    "Logon",          "lsass.exe",      "System Check",              1.0),
    (4624, "Information", "Security", "Logon",    "Logon",          "winlogon.exe",   "User Authentication",        1.0),
    (4624, "Information", "Security", "Logon",    "Logon",          "svchost.exe",    "Service Startup",            1.0),
    # Process creation (benign)
    (4688, "Information", "Security", "Exec",     "Process Creation","explorer.exe",  "System Check",              1.0),
    (4688, "Information", "Security", "Exec",     "Process Creation","chrome.exe",    "Browser Launch",             1.0),
    (4688, "Information", "Security", "Exec",     "Process Creation","notepad.exe",   "Text Editor",                1.0),
    (4688, "Information", "Security", "Exec",     "Process Creation","cmd.exe",       "Command Prompt",             1.0),
    (4688, "Information", "Security", "Exec",     "Process Creation","msiexec.exe",   "Software Install",           1.0),
]

SUSPICIOUS_EVENTS = [
    # PowerShell execution
    (4688, "Warning",    "Security", "Exec",     "Process Creation","powershell.exe", "Encoded IEX Download",       0.8),
    (4688, "Warning",    "Security", "Exec",     "Process Creation","powershell.exe", "Bypass Execution Policy",    0.8),
    (4688, "Warning",    "Security", "Exec",     "Process Creation","cmd.exe",        "Net User Enumeration",       0.9),
    (4688, "Warning",    "Security", "Exec",     "Process Creation","wscript.exe",    "VBS Script Execution",       0.7),
    (4688, "Warning",    "Security", "Exec",     "Process Creation","mshta.exe",      "HTA Script Execution",       0.7),
]

CRITICAL_EVENTS = [
    # LSASS dump (credential access)
    (10,   "Critical",   "Sysmon",   "Read",     "Process Access",  "mimikatz.exe",   "LSASS Dump",                0.0),
    (10,   "Critical",   "Sysmon",   "Read",     "Process Access",  "procdump.exe",   "LSASS Dump",                0.0),
    # Lateral movement
    (4688, "Critical",   "Security", "Exec",     "Process Creation","psexec.exe",     "Remote Execution via SMB",  0.0),
    (4688, "Critical",   "Security", "Exec",     "Process Creation","wmiexec.exe",    "WMI Remote Execution",      0.0),
    # Persistence
    (4688, "Critical",   "Security", "Exec",     "Process Creation","schtasks.exe",   "Scheduled Task Created",    0.5),
    (4688, "Critical",   "Security", "Exec",     "Process Creation","reg.exe",        "Registry Run Key Modified", 0.5),
    # Exfiltration
    (4688, "Critical",   "Security", "Exec",     "Process Creation","curl.exe",       "Data Exfiltration via HTTP",0.3),
    (4688, "Critical",   "Security", "Exec",     "Process Creation","certutil.exe",   "Base64 Encoded Transfer",   0.3),
    # Token abuse
    (4688, "Critical",   "Security", "Exec",     "Process Creation","lsass.exe",      "Token Impersonation",       0.0),
]

# ─── RESOURCE USAGE PROFILES ───────────────────────────────────────────────────

def gen_resource_usage(level: str):
    """Generate realistic CPU, memory, and network_io values per threat level."""
    if level == "Critical":
        cpu     = round(random.uniform(45.0, 98.0), 1)
        mem     = random.randint(600, 1800)
        net_io  = round(random.uniform(5.0, 90.0), 1)
    elif level == "Warning":
        cpu     = round(random.uniform(10.0, 55.0), 1)
        mem     = random.randint(150, 700)
        net_io  = round(random.uniform(0.5, 30.0), 1)
    else:  # Information / Normal
        cpu     = round(random.uniform(0.1, 12.0), 1)
        mem     = random.randint(30, 250)
        net_io  = round(random.uniform(0.0, 5.0), 1)
    return cpu, mem, net_io


# ─── ROW GENERATOR ─────────────────────────────────────────────────────────────

def generate_row(timestamp: datetime, attack_burst: bool = False):
    """Generate a single log row."""
    r = random.random()

    if attack_burst:
        # During an attack burst — heavily weighted to critical/suspicious
        if r < 0.60:
            template = random.choice(CRITICAL_EVENTS)
        elif r < 0.85:
            template = random.choice(SUSPICIOUS_EVENTS)
        else:
            template = random.choice(NORMAL_EVENTS)
    else:
        # Normal background traffic — mostly benign
        if r < 0.015:    # ~1.5% critical
            template = random.choice(CRITICAL_EVENTS)
        elif r < 0.06:   # ~4.5% suspicious
            template = random.choice(SUSPICIOUS_EVENTS)
        else:
            template = random.choice(NORMAL_EVENTS)

    event_id, level, source, opcode, task_cat, process_name, detail, signed_prob = template
    cpu, mem, net_io = gen_resource_usage(level)
    is_signed = 1 if random.random() < signed_prob else 0

    # Pick a computer and user
    computer = random.choice(COMPUTERS)
    user = random.choice(USERS)

    # Integrity level is more "System" for critical events
    if level == "Critical":
        integrity = random.choice(["High", "System", "System"])
    elif level == "Warning":
        integrity = random.choice(["Medium", "High"])
    else:
        integrity = random.choice(INTEGRITY_LEVELS)

    pid = random.randint(300, 12000)

    return [
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        event_id,
        level,
        source,
        computer,
        user,
        opcode,
        task_cat,
        pid,
        process_name,
        detail,
        cpu,
        mem,
        net_io,
        integrity,
        is_signed,
    ]


# ─── DATASET GENERATOR ─────────────────────────────────────────────────────────

def generate_dataset(num_rows: int, output_file: str):
    """Generate a full dataset CSV with realistic attack bursts embedded."""

    print(f"\n[+] Generating {num_rows:,} rows → {output_file}")

    # Place 3-6 attack bursts randomly distributed in the timeline
    num_bursts = random.randint(3, 6)
    burst_centers = sorted(random.sample(range(1000, num_rows - 500), num_bursts))
    burst_radius  = 50  # rows around each burst center that are suspicious/critical
    burst_set     = set()
    for center in burst_centers:
        for offset in range(-burst_radius, burst_radius + 1):
            burst_set.add(center + offset)

    # Start timestamp: random date in the past 30 days
    base_time = datetime(2026, 4, 1, 22, 49, 12)

    header = [
        "timestamp", "event_id", "level", "source", "computer", "user",
        "opcode", "task_category", "process_id", "process_name",
        "detail", "cpu_usage", "mem_usage", "network_io",
        "integrity_level", "is_signed"
        # NO label column — intentional
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        current_time = base_time
        for i in range(num_rows):
            # Advance time by 1-3 seconds per row
            current_time += timedelta(seconds=random.randint(1, 3))
            in_burst = i in burst_set
            row = generate_row(current_time, attack_burst=in_burst)
            writer.writerow(row)

            if (i + 1) % 10000 == 0:
                print(f"    {i + 1:,} / {num_rows:,} rows written...")

    size_kb = os.path.getsize(output_file) / 1024
    print(f"[✓] Done! File: {output_file}  ({size_kb:.1f} KB)")


# ─── ENTRY POINT ───────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args:
        # Default: generate a 10k dataset
        generate_dataset(10_000, "soc_logs_10k.csv")
        return

    # If args are all numbers → generate one file per size
    sizes = []
    custom_file = None

    for arg in args:
        try:
            sizes.append(int(arg))
        except ValueError:
            custom_file = arg  # treat non-number as output filename

    if not sizes:
        print("Usage: python generate_dataset.py 10000 [50000] [100000] [output_name.csv]")
        sys.exit(1)

    for i, size in enumerate(sizes):
        if custom_file and len(sizes) == 1:
            filename = custom_file
        else:
            filename = f"soc_logs_{size // 1000}k.csv"
        generate_dataset(size, filename)

    print("\n[✓] All datasets generated successfully!")


if __name__ == "__main__":
    main()
