"""
Render the final AnalystReport as a Markdown file.
"""

from datetime import datetime, timezone
from pathlib import Path

from schemas import AnalystReport, ConfidenceLevel, IOCType


_CONFIDENCE_BADGE = {
    ConfidenceLevel.HIGH: "🔴 HIGH",
    ConfidenceLevel.MEDIUM: "🟡 MEDIUM",
    ConfidenceLevel.LOW: "⚪ LOW",
}

_IOC_TYPE_LABEL = {
    IOCType.IPV4: "IPv4",
    IOCType.DOMAIN: "Domain",
    IOCType.URL: "URL",
    IOCType.MD5: "MD5",
    IOCType.SHA1: "SHA1",
    IOCType.SHA256: "SHA256",
    IOCType.EMAIL: "Email",
}


def write_report(report: AnalystReport, output_path: str) -> None:
    md = _render(report)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(md, encoding="utf-8")


def _render(r: AnalystReport) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# AI SOC Assistant — DRAFT Analyst Report",
        "",
        f"> **STATUS: DRAFT — ALL FINDINGS REQUIRE ANALYST REVIEW BEFORE ACTION**",
        "",
        f"- **Input file:** `{r.input_file}`",
        f"- **Generated:** {now}",
        f"- **IOCs extracted:** {len(r.iocs)}",
        f"- **MITRE candidates:** {len(r.mitre_mappings)}",
        f"- **Detection rules drafted:** {len(r.detection_rules)}",
        "",
    ]

    # ── Safety findings ──────────────────────────────────────────────────────
    if r.safety_findings:
        lines += ["## ⚠️ Safety Flags", ""]
        lines += [
            "> The following patterns were detected in the input. "
            "Review before trusting this report.",
            "",
        ]
        for f in r.safety_findings:
            lines += [
                f"### [{f.severity.upper()}] {f.matched_pattern}",
                f"- **Category:** {f.category}",
                f"- **Excerpt:** `{f.excerpt}`",
                "",
            ]
    else:
        lines += ["## Safety Flags", "", "_No safety concerns detected._", ""]

    # ── Executive Summary ────────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        r.summary,
        "",
    ]

    # ── IOCs ─────────────────────────────────────────────────────────────────
    lines += ["## Indicators of Compromise (IOCs)", ""]

    if r.iocs:
        lines += [
            "| Type | Value | Confidence | Source | Regex Confirmed |",
            "|------|-------|-----------|--------|-----------------|",
        ]
        for ioc in r.iocs:
            badge = _CONFIDENCE_BADGE[ioc.confidence]
            confirmed = "Yes" if ioc.regex_confirmed else "No"
            type_label = _IOC_TYPE_LABEL.get(ioc.ioc_type, ioc.ioc_type.value)
            # Truncate very long values (URLs)
            val = ioc.value if len(ioc.value) <= 80 else ioc.value[:77] + "..."
            lines.append(
                f"| {type_label} | `{val}` | {badge} | {ioc.source} | {confirmed} |"
            )
        lines.append("")
    else:
        lines += ["_No IOCs identified._", ""]

    # ── Attacker Behaviors ───────────────────────────────────────────────────
    lines += ["## Attacker Behaviors", ""]

    if r.attacker_behaviors:
        for b in r.attacker_behaviors:
            lines.append(f"- {b}")
        lines.append("")
    else:
        lines += ["_No behaviors identified._", ""]

    # ── MITRE ATT&CK Mappings ────────────────────────────────────────────────
    lines += ["## MITRE ATT&CK Candidates", ""]

    if r.mitre_mappings:
        lines += [
            "| Technique | Name | Tactic | Confidence | Evidence |",
            "|-----------|------|--------|-----------|----------|",
        ]
        for m in r.mitre_mappings:
            badge = _CONFIDENCE_BADGE[m.confidence]
            evidence = m.evidence[:100].replace("|", "\\|")
            lines.append(
                f"| [{m.technique_id}](https://attack.mitre.org/techniques/"
                f"{m.technique_id.replace('.', '/')}) "
                f"| {m.technique_name} | {m.tactic} | {badge} | {evidence} |"
            )
        lines.append("")
    else:
        lines += ["_No MITRE mappings identified._", ""]

    # ── Detection Hypotheses ─────────────────────────────────────────────────
    if r.detection_hypotheses:
        lines += ["## Detection Hypotheses (LLM-Generated)", ""]
        for h in r.detection_hypotheses:
            lines.append(f"- {h}")
        lines.append("")

    # ── Detection Rules ──────────────────────────────────────────────────────
    lines += ["## Draft Detection Rules (Sigma-Style)", ""]

    if r.detection_rules:
        lines += [
            "> **DRAFT ONLY** — Rules must be reviewed, tested in a staging environment,",
            "> and approved by your detection engineering team before deployment.",
            "",
        ]
        for rule in r.detection_rules:
            lines += [
                f"### {rule.title}",
                f"**Basis:** {rule.basis}",
                "",
                f"_{rule.description}_",
                "",
                "```yaml",
                rule.rule_yaml.rstrip(),
                "```",
                "",
            ]
    else:
        lines += ["_No detection rules generated._", ""]

    # ── Uncertainties ────────────────────────────────────────────────────────
    if r.uncertainties:
        lines += ["## Uncertainties & Analyst Notes", ""]
        for u in r.uncertainties:
            lines.append(f"- {u}")
        lines.append("")

    # ── Analyst Review Checklist ─────────────────────────────────────────────
    lines += [
        "## Analyst Review Checklist",
        "",
        "Complete all items before this report leaves DRAFT status.",
        "",
        "- [ ] Reviewed all safety flags above",
        "- [ ] Verified each IOC against threat intel feeds or historical data",
        "- [ ] Removed or reclassified any IOCs that appear to be false positives",
        "- [ ] Reviewed all MITRE ATT&CK mappings — removed or corrected mismatches",
        "- [ ] Reviewed each draft detection rule for logic errors and false positive risk",
        "- [ ] Tested detection rules in a non-production environment before deployment",
        "- [ ] Shared IOCs with TIP/SIEM team for blocking/alerting",
        "- [ ] Assessed whether incident response or threat hunting is warranted",
        "- [ ] Documented final disposition and sign-off",
        "",
        "---",
        "",
        "_Generated by ai_soc_assistant (proof-of-concept). "
        "AI output is advisory only. Not a substitute for analyst judgment._",
    ]

    return "\n".join(lines) + "\n"
