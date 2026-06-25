"""
Local keyword-to-MITRE ATT&CK mapping.

This is deliberately a hard-coded dictionary — no network calls, no external data.
The LLM already supplies its own MITRE candidates; this module adds a deterministic
second pass over attacker behaviors using keyword matching.
"""

from schemas import MITRECandidate, ConfidenceLevel

# ---------------------------------------------------------------------------
# Keyword → ATT&CK mapping
# Each entry: (technique_id, technique_name, tactic, [keywords])
# ---------------------------------------------------------------------------
_TECHNIQUE_MAP: list[tuple[str, str, str, list[str]]] = [
    # Initial Access
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
     ["phishing", "spearphish", "malicious attachment", "malicious email", "lure", "malspam"]),
    ("T1566.002", "Phishing: Spearphishing Link", "Initial Access",
     ["phishing link", "malicious link", "malicious url", "credential harvesting link"]),
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     ["exploit", "rce", "remote code execution", "vulnerability", "cve", "0day", "zero-day",
      "zero day", "sql injection", "sqli", "log4j", "log4shell"]),
    ("T1078", "Valid Accounts", "Initial Access",
     ["valid account", "compromised credential", "stolen credential", "stolen password",
      "credential stuffing", "brute force login"]),

    # Execution
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
     ["powershell", "powershell.exe", "invoke-expression", "iex", "encoded command"]),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution",
     ["cmd.exe", "command shell", "cmd /c", "batch script"]),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution",
     ["javascript", "wscript", "cscript", "jscript", ".js payload"]),
    ("T1059.006", "Command and Scripting Interpreter: Python", "Execution",
     ["python script", "python payload", "python malware"]),
    ("T1204.002", "User Execution: Malicious File", "Execution",
     ["user opened", "user executed", "double-clicked", "ran the attachment", "macro enabled"]),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution",
     ["scheduled task", "schtasks", "task scheduler", "cron job", "persistence via task"]),

    # Persistence
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence",
     ["registry run key", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
      "hklm\\software\\microsoft\\windows\\currentversion\\run", "autorun"]),
    ("T1505.003", "Server Software Component: Web Shell", "Persistence",
     ["webshell", "web shell", "asp shell", "php shell", "jsp shell", "aspx shell"]),
    ("T1136", "Create Account", "Persistence",
     ["created account", "new admin account", "backdoor account", "rogue account"]),

    # Privilege Escalation
    ("T1055", "Process Injection", "Privilege Escalation",
     ["process injection", "dll injection", "code injection", "process hollowing",
      "reflective dll", "shellcode injection"]),
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
     ["privilege escalation exploit", "local privilege escalation", "lpe", "elevation exploit"]),
    ("T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC", "Privilege Escalation",
     ["uac bypass", "user account control bypass", "eventvwr", "fodhelper"]),

    # Defense Evasion
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
     ["disabled antivirus", "disabled defender", "killed av", "tamper protection",
      "security software disabled", "edr disabled", "stopped security"]),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
     ["obfuscated", "base64 encoded", "encoded payload", "packed binary", "encrypted payload",
      "xor encoded", "hex encoded"]),
    ("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion",
     ["deleted logs", "cleared logs", "removed evidence", "wiped files", "log cleared",
      "event log cleared"]),
    ("T1036", "Masquerading", "Defense Evasion",
     ["masquerade", "renamed binary", "disguised as", "impersonating", "living off the land",
      "lolbin", "lolbas"]),

    # Credential Access
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
     ["lsass", "credential dump", "mimikatz", "sekurlsa", "dump credentials",
      "wce.exe", "procdump lsass"]),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access",
     ["credentials in file", "plaintext password", "hardcoded password", "password in config"]),
    ("T1110", "Brute Force", "Credential Access",
     ["brute force", "password spray", "credential stuffing", "dictionary attack"]),

    # Discovery
    ("T1082", "System Information Discovery", "Discovery",
     ["system information", "systeminfo", "whoami", "hostname", "os version", "uname -a"]),
    ("T1083", "File and Directory Discovery", "Discovery",
     ["directory listing", "file listing", "dir command", "ls -la", "find files"]),
    ("T1046", "Network Service Discovery", "Discovery",
     ["port scan", "nmap", "network scan", "service enumeration", "masscan"]),
    ("T1057", "Process Discovery", "Discovery",
     ["process list", "tasklist", "ps aux", "running processes"]),

    # Lateral Movement
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
     ["rdp", "remote desktop", "mstsc", "remote desktop protocol"]),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
     ["smb", "psexec", "wmic", "admin share", "ipc$", "lateral movement via smb"]),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement",
     ["pass the hash", "pth", "ntlm hash", "hash passing"]),

    # Collection
    ("T1005", "Data from Local System", "Collection",
     ["collected files", "data exfiltration from local", "staged data", "archiving files"]),
    ("T1056.001", "Input Capture: Keylogging", "Collection",
     ["keylogger", "keystroke", "keyboard capture", "key logging"]),
    ("T1113", "Screen Capture", "Collection",
     ["screenshot", "screen capture", "screengrab"]),

    # Command and Control
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
     ["http c2", "https c2", "beacon", "c2 over http", "c2 over https", "web-based c2"]),
    ("T1071.004", "Application Layer Protocol: DNS", "Command and Control",
     ["dns c2", "dns tunneling", "dns exfiltration", "dnscat"]),
    ("T1095", "Non-Application Layer Protocol", "Command and Control",
     ["raw socket", "icmp tunnel", "custom protocol c2"]),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     ["downloaded tool", "dropped payload", "fetched binary", "certutil download",
      "bitsadmin download", "wget payload", "curl payload"]),

    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     ["exfiltrated", "data theft", "data stolen", "exfiltration over c2",
      "data sent to attacker", "sent to command and control"]),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration",
     ["exfiltration via cloud", "data uploaded to", "exfil via dropbox", "mega upload",
      "pastebin exfil"]),

    # Impact
    ("T1486", "Data Encrypted for Impact", "Impact",
     ["ransomware", "encrypted files", "ransom note", "files encrypted", "bitcoin ransom",
      "decrypt key", ".locked", ".encrypted"]),
    ("T1490", "Inhibit System Recovery", "Impact",
     ["shadow copy deleted", "vssadmin delete", "backup deleted", "recovery disabled",
      "bcdedit", "wbadmin delete"]),
    ("T1489", "Service Stop", "Impact",
     ["stopped services", "killed processes", "service disabled", "process terminated"]),
]


def map_behaviors_to_mitre(behaviors: list[str]) -> list[MITRECandidate]:
    """
    Match attacker behaviors against the keyword dictionary.
    Returns de-duplicated MITRE candidates (by technique_id).
    Confidence is always MEDIUM because this is keyword-only matching.
    """
    found: dict[str, MITRECandidate] = {}

    for behavior in behaviors:
        lower = behavior.lower()
        for tech_id, tech_name, tactic, keywords in _TECHNIQUE_MAP:
            if tech_id in found:
                continue
            for kw in keywords:
                if kw in lower:
                    found[tech_id] = MITRECandidate(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic=tactic,
                        confidence=ConfidenceLevel.MEDIUM,
                        evidence=f"Matched keyword '{kw}' in behavior: \"{behavior}\"",
                    )
                    break

    return list(found.values())


def merge_mitre_candidates(
    keyword_hits: list[MITRECandidate],
    llm_hits: list[dict],
) -> list[MITRECandidate]:
    """
    Merge keyword-matched and LLM-suggested MITRE candidates.
    LLM candidates that are already keyword-confirmed are upgraded to HIGH confidence.
    Deduplicated by technique_id.
    """
    merged: dict[str, MITRECandidate] = {c.technique_id: c for c in keyword_hits}

    for raw in llm_hits:
        try:
            tech_id = raw.get("technique_id", "").strip()
            if not tech_id:
                continue

            confidence_str = raw.get("confidence", "low").lower()
            confidence = {
                "high": ConfidenceLevel.HIGH,
                "medium": ConfidenceLevel.MEDIUM,
                "low": ConfidenceLevel.LOW,
            }.get(confidence_str, ConfidenceLevel.LOW)

            candidate = MITRECandidate(
                technique_id=tech_id,
                technique_name=raw.get("technique_name", "Unknown"),
                tactic=raw.get("tactic", "Unknown"),
                confidence=confidence,
                evidence=raw.get("evidence", "LLM-suggested (no direct quote)"),
            )

            if tech_id in merged:
                # Keyword + LLM agreement → HIGH confidence
                merged[tech_id] = merged[tech_id].model_copy(
                    update={"confidence": ConfidenceLevel.HIGH}
                )
            else:
                merged[tech_id] = candidate

        except Exception:
            continue

    return list(merged.values())
