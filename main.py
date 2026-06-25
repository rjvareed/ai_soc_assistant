"""
AI SOC Assistant — CLI entrypoint.

Usage:
    python main.py --input sample_reports/report.txt --output outputs/report.md

All AI output is DRAFT and requires analyst review before action.
"""

import argparse
import json
import sys

from dotenv import load_dotenv
load_dotenv()

from ingest import load_and_normalize
from safety import run_safety_checks
from ioc_extract import extract_iocs, merge_with_llm_iocs
from llm_client import call_llm
from mitre_mapper import map_behaviors_to_mitre, merge_mitre_candidates
from detection_generator import generate_detection_rules
from report_writer import write_report
from schemas import AnalystReport


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI SOC Assistant — turns threat reports into structured analyst reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "All output is DRAFT and requires analyst review before action.\n"
            "API key must be set in ANTHROPIC_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="FILE",
        help="Path to the input threat report (.txt or similar text file)",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        metavar="FILE",
        help="Path for the output Markdown report",
    )
    parser.add_argument(
        "--model", "-m",
        default="claude-opus-4-8",
        metavar="MODEL",
        help="Claude model ID to use (default: claude-opus-4-8)",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Run only local analysis (no LLM call) — useful for testing without an API key",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print progress to stderr",
    )
    return parser.parse_args()


def _log(msg: str, verbose: bool) -> None:
    if verbose:
        print(f"[ai_soc] {msg}", file=sys.stderr)


def main() -> None:
    args = _parse_args()

    # 1. Ingest & normalize
    _log(f"Loading {args.input!r}...", args.verbose)
    try:
        text = load_and_normalize(args.input)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    _log(f"Loaded {len(text):,} characters.", args.verbose)

    # 2. Safety checks
    _log("Running safety checks...", args.verbose)
    safety_findings = run_safety_checks(text)
    if safety_findings:
        print(
            f"[ai_soc] WARNING: {len(safety_findings)} safety flag(s) detected. "
            "Review the report before action.",
            file=sys.stderr,
        )

    # 3. Regex IOC extraction
    _log("Extracting IOCs via regex...", args.verbose)
    regex_iocs = extract_iocs(text)
    _log(f"Regex found {len(regex_iocs)} IOC(s).", args.verbose)

    # 4. LLM analysis
    llm_result = None
    llm_raw = None

    if not args.skip_llm:
        _log(f"Calling LLM for structured analysis (model: {args.model})...", args.verbose)
        try:
            llm_result = call_llm(text, model=args.model)
            llm_raw = llm_result.model_dump()
            _log("LLM response received and validated.", args.verbose)
        except ValueError as exc:
            print(f"[ai_soc] WARNING: LLM call failed — {exc}", file=sys.stderr)
            print("[ai_soc] Continuing with regex-only results.", file=sys.stderr)
    else:
        _log("Skipping LLM (--skip-llm flag set).", args.verbose)

    # 5. Merge IOCs
    llm_ioc_candidates = llm_result.candidate_iocs if llm_result else []
    merged_iocs = merge_with_llm_iocs(regex_iocs, llm_ioc_candidates)
    _log(f"Merged IOC list: {len(merged_iocs)} total.", args.verbose)

    # 6. MITRE mapping
    attacker_behaviors = llm_result.attacker_behaviors if llm_result else []
    keyword_mitre = map_behaviors_to_mitre(attacker_behaviors)
    llm_mitre = llm_result.mitre_candidates if llm_result else []
    merged_mitre = merge_mitre_candidates(keyword_mitre, llm_mitre)
    _log(f"MITRE candidates: {len(merged_mitre)}.", args.verbose)

    # 7. Detection rules
    detection_hypotheses = llm_result.detection_hypotheses if llm_result else []
    detection_rules = generate_detection_rules(merged_iocs, merged_mitre, detection_hypotheses)
    _log(f"Detection rules drafted: {len(detection_rules)}.", args.verbose)

    # 8. Assemble report
    summary = (
        llm_result.summary
        if llm_result
        else "(LLM summary unavailable — ran in local-only mode)"
    )
    uncertainties = llm_result.uncertainties if llm_result else []

    report = AnalystReport(
        input_file=args.input,
        safety_findings=safety_findings,
        summary=summary,
        iocs=merged_iocs,
        attacker_behaviors=attacker_behaviors,
        mitre_mappings=merged_mitre,
        detection_rules=detection_rules,
        detection_hypotheses=detection_hypotheses,
        uncertainties=uncertainties,
        llm_raw_response=llm_raw,
    )

    # 9. Write output
    _log(f"Writing report to {args.output!r}...", args.verbose)
    write_report(report, args.output)

    print(f"[ai_soc] DRAFT report written to: {args.output}")
    print(
        f"[ai_soc] Summary: {len(merged_iocs)} IOCs | "
        f"{len(merged_mitre)} MITRE candidates | "
        f"{len(detection_rules)} draft rules | "
        f"{len(safety_findings)} safety flag(s)"
    )
    if safety_findings:
        print("[ai_soc] *** ANALYST: Review safety flags before trusting this report. ***")


if __name__ == "__main__":
    main()
