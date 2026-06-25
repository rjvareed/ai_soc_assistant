"""
Draft Sigma-style detection rules from IOCs and MITRE candidates.

Rules are DRAFT only — marked with status: experimental and must be reviewed
by an analyst before deployment.
"""

import textwrap
from schemas import IOC, IOCType, MITRECandidate, DetectionRule


def generate_detection_rules(
    iocs: list[IOC],
    mitre_candidates: list[MITRECandidate],
    detection_hypotheses: list[str],
) -> list[DetectionRule]:
    rules: list[DetectionRule] = []

    rules.extend(_rules_from_iocs(iocs))
    rules.extend(_rules_from_mitre(mitre_candidates))
    rules.extend(_rules_from_hypotheses(detection_hypotheses))

    # Deduplicate by title
    seen_titles: set[str] = set()
    unique: list[DetectionRule] = []
    for rule in rules:
        if rule.title not in seen_titles:
            seen_titles.add(rule.title)
            unique.append(rule)

    return unique


def _list_values(items: list[str], indent: int = 6) -> str:
    """Format a list of strings as indented YAML list items."""
    pad = " " * indent
    return "\n".join(f"{pad}- '{v}'" for v in items)


def _rules_from_iocs(iocs: list[IOC]) -> list[DetectionRule]:
    rules: list[DetectionRule] = []

    ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
    domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
    url_iocs = [i for i in iocs if i.ioc_type == IOCType.URL]
    hash_iocs = [i for i in iocs if i.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)]

    if ip_iocs:
        values = _list_values([i.value for i in ip_iocs[:20]])
        rules.append(DetectionRule(
            title="DRAFT - Network Connection to Threat Report IPs",
            description="Detects network connections to IP addresses extracted from the threat report.",
            basis=f"{len(ip_iocs)} IP IOC(s) from report",
            rule_yaml=(
                "title: DRAFT - Network Connection to Threat Report IPs\n"
                "status: experimental\n"
                "description: >\n"
                "  ANALYST REVIEW REQUIRED. Detects network connections to IP addresses\n"
                "  extracted from the threat report. Verify each IP before deployment.\n"
                "logsource:\n"
                "  category: network_connection\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    DestinationIp|contains:\n"
                f"{values}\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - Legitimate services on these IPs\n"
                "  - Analyst must verify each IP\n"
                "level: medium\n"
                "tags:\n"
                "  - tlp:amber\n"
                "  - draft\n"
            ),
        ))

    if domain_iocs:
        values = _list_values([i.value for i in domain_iocs[:20]])
        rules.append(DetectionRule(
            title="DRAFT - DNS Query to Threat Report Domains",
            description="Detects DNS queries to domains extracted from the threat report.",
            basis=f"{len(domain_iocs)} domain IOC(s) from report",
            rule_yaml=(
                "title: DRAFT - DNS Query to Threat Report Domains\n"
                "status: experimental\n"
                "description: >\n"
                "  ANALYST REVIEW REQUIRED. Detects DNS queries matching domains extracted\n"
                "  from the threat report. Review for CDN/shared hosting false positives.\n"
                "logsource:\n"
                "  category: dns\n"
                "detection:\n"
                "  selection:\n"
                "    QueryName|contains:\n"
                f"{values}\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - Shared hosting / CDN may cause FPs\n"
                "  - Analyst must verify domain ownership\n"
                "level: medium\n"
                "tags:\n"
                "  - tlp:amber\n"
                "  - draft\n"
            ),
        ))

    if url_iocs:
        values = _list_values([i.value[:120] for i in url_iocs[:10]])
        rules.append(DetectionRule(
            title="DRAFT - HTTP Request Matching Threat Report URLs",
            description="Detects HTTP/S requests to URLs extracted from the threat report.",
            basis=f"{len(url_iocs)} URL IOC(s) from report",
            rule_yaml=(
                "title: DRAFT - HTTP Request Matching Threat Report URLs\n"
                "status: experimental\n"
                "description: >\n"
                "  ANALYST REVIEW REQUIRED. Detects web proxy/firewall log entries matching\n"
                "  URLs from the threat report.\n"
                "logsource:\n"
                "  category: proxy\n"
                "detection:\n"
                "  selection:\n"
                "    c-uri|contains:\n"
                f"{values}\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - URL path may appear on legitimate sites\n"
                "level: high\n"
                "tags:\n"
                "  - tlp:amber\n"
                "  - draft\n"
            ),
        ))

    if hash_iocs:
        values = _list_values([i.value for i in hash_iocs[:20]])
        rules.append(DetectionRule(
            title="DRAFT - File Hash Match from Threat Report",
            description="Detects execution or presence of files matching hashes from the threat report.",
            basis=f"{len(hash_iocs)} hash IOC(s) from report",
            rule_yaml=(
                "title: DRAFT - File Hash Match from Threat Report\n"
                "status: experimental\n"
                "description: >\n"
                "  ANALYST REVIEW REQUIRED. Detects process creation or file events matching\n"
                "  hashes extracted from the threat report.\n"
                "logsource:\n"
                "  category: process_creation\n"
                "  product: windows\n"
                "detection:\n"
                "  selection:\n"
                "    Hashes|contains:\n"
                f"{values}\n"
                "  condition: selection\n"
                "falsepositives:\n"
                "  - Unlikely, but confirm hash source\n"
                "level: high\n"
                "tags:\n"
                "  - tlp:amber\n"
                "  - draft\n"
            ),
        ))

    return rules


_MITRE_RULE_TEMPLATES: dict[str, str] = {
    "T1059.001": textwrap.dedent("""\
        title: DRAFT - Suspicious PowerShell Execution (Threat Report)
        status: experimental
        description: ANALYST REVIEW REQUIRED. PowerShell usage consistent with TTPs in threat report.
        logsource:
          category: process_creation
          product: windows
        detection:
          selection:
            Image|endswith: '\\powershell.exe'
            CommandLine|contains:
              - '-EncodedCommand'
              - '-enc '
              - 'Invoke-Expression'
              - 'IEX('
              - 'DownloadString'
              - 'bypass'
          condition: selection
        falsepositives:
          - Legitimate admin scripts
        level: medium
        tags:
          - attack.execution
          - attack.t1059.001
          - draft
        """),
    "T1003.001": textwrap.dedent("""\
        title: DRAFT - LSASS Memory Access (Threat Report)
        status: experimental
        description: ANALYST REVIEW REQUIRED. LSASS access consistent with credential dumping TTPs in report.
        logsource:
          category: process_access
          product: windows
        detection:
          selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess|contains:
              - '0x1010'
              - '0x1410'
              - '0x1038'
              - '0x40'
        filter_legitimate:
          SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csrss.exe'
        condition: selection and not filter_legitimate
        falsepositives:
          - AV/EDR products, Windows system processes
        level: high
        tags:
          - attack.credential_access
          - attack.t1003.001
          - draft
        """),
    "T1486": textwrap.dedent("""\
        title: DRAFT - Mass File Encryption Activity (Threat Report)
        status: experimental
        description: ANALYST REVIEW REQUIRED. File encryption pattern consistent with ransomware in report.
        logsource:
          category: file_event
          product: windows
        detection:
          selection:
            TargetFilename|endswith:
              - '.locked'
              - '.encrypted'
              - '.enc'
              - '.ransom'
              - '.crypted'
          condition: selection
        falsepositives:
          - Encryption software on specific file types
        level: critical
        tags:
          - attack.impact
          - attack.t1486
          - draft
        """),
    "T1566.001": textwrap.dedent("""\
        title: DRAFT - Phishing Email with Malicious Attachment (Threat Report)
        status: experimental
        description: ANALYST REVIEW REQUIRED. Email pattern consistent with phishing TTPs in report.
        logsource:
          category: email
        detection:
          selection:
            Attachment|endswith:
              - '.doc'
              - '.docm'
              - '.xls'
              - '.xlsm'
              - '.iso'
              - '.lnk'
              - '.vbs'
              - '.js'
          condition: selection
        falsepositives:
          - Legitimate business attachments — tune on sender or subject
        level: medium
        tags:
          - attack.initial_access
          - attack.t1566.001
          - draft
        """),
    "T1505.003": textwrap.dedent("""\
        title: DRAFT - Web Shell File Write (Threat Report)
        status: experimental
        description: ANALYST REVIEW REQUIRED. Web shell activity consistent with TTPs in report.
        logsource:
          category: file_event
          product: windows
        detection:
          selection:
            TargetFilename|contains:
              - '\\inetpub\\'
              - '\\wwwroot\\'
            TargetFilename|endswith:
              - '.aspx'
              - '.asp'
              - '.php'
              - '.jsp'
        filter_known_good:
          Image|endswith:
            - '\\w3wp.exe'
        condition: selection and not filter_known_good
        falsepositives:
          - Legitimate web app deployments
        level: high
        tags:
          - attack.persistence
          - attack.t1505.003
          - draft
        """),
}


def _rules_from_mitre(candidates: list[MITRECandidate]) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    for candidate in candidates:
        template = _MITRE_RULE_TEMPLATES.get(candidate.technique_id)
        if template:
            rules.append(DetectionRule(
                title=f"DRAFT - {candidate.technique_name} ({candidate.technique_id})",
                description=(
                    f"Detection for {candidate.tactic}/{candidate.technique_id} "
                    f"based on threat report analysis."
                ),
                basis=f"MITRE {candidate.technique_id}: {candidate.evidence[:120]}",
                rule_yaml=template,
            ))
    return rules


def _rules_from_hypotheses(hypotheses: list[str]) -> list[DetectionRule]:
    """Convert LLM detection hypotheses into stub rules for analyst development."""
    rules: list[DetectionRule] = []
    for i, hyp in enumerate(hypotheses, 1):
        short = hyp[:80].replace('"', "'")
        rules.append(DetectionRule(
            title=f"DRAFT - Detection Hypothesis {i}",
            description=f"Stub rule for analyst: {hyp}",
            basis=f"LLM detection hypothesis: {hyp[:120]}",
            rule_yaml=textwrap.dedent(f"""\
                title: 'DRAFT - Detection Hypothesis {i}'
                status: experimental
                description: >
                  ANALYST REVIEW REQUIRED. This is a stub rule generated from an LLM
                  detection hypothesis. The analyst must define the logsource and
                  detection logic before deployment.
                  Hypothesis: {short}
                logsource:
                  # TODO: specify category and product
                  category: TBD
                detection:
                  # TODO: define detection logic
                  selection:
                    placeholder: 'REPLACE_WITH_REAL_CONDITION'
                  condition: selection
                falsepositives:
                  - Unknown — analyst must assess
                level: medium
                tags:
                  - draft
                  - needs-analyst-review
                """),
        ))
    return rules
