# ai_soc_assistant

A Python proof-of-concept that turns threat reports, blog posts, and incident notes into structured analyst reports. Combines deterministic regex analysis with Claude AI to extract IOCs, map MITRE ATT&CK techniques, and draft Sigma-style detection rules.

**All AI output is DRAFT. Every finding requires analyst review before action.**

## What it does

1. **Ingests** a text-based threat report (up to 500 KB)
2. **Safety checks** — detects prompt injection attempts and sensitive data before the text reaches the LLM
3. **Regex IOC extraction** — deterministically finds IPv4s, domains, URLs, hashes (MD5/SHA1/SHA256), and emails
4. **LLM analysis** — sends the report to Claude (`claude-opus-4-8`) for executive summary, attacker behaviors, additional IOC candidates, MITRE ATT&CK suggestions, detection hypotheses, and uncertainties
5. **Merges** regex and LLM IOCs; assigns confidence (HIGH = regex-confirmed, MEDIUM = LLM + regex-valid, LOW = LLM-only)
6. **MITRE mapping** — keyword dictionary + LLM candidates, deduped and confidence-scored
7. **Draft detection rules** — Sigma-style YAML rules for IOC types and MITRE techniques, plus stubs for LLM hypotheses
8. **Markdown report** — structured output with IOC table, MITRE table, detection rules, and a mandatory analyst review checklist

## Project structure

```
ai_soc_assistant/
├── main.py                  # CLI entrypoint
├── schemas.py               # Pydantic data models
├── ingest.py                # File loading and text normalization
├── safety.py                # Prompt injection + sensitive data detection
├── ioc_extract.py           # Regex IOC extraction and LLM merge
├── mitre_mapper.py          # Keyword-to-ATT&CK mapping + LLM merge
├── detection_generator.py   # Draft Sigma-style rule generation
├── report_writer.py         # Markdown report renderer
├── llm_client.py            # Claude API integration
├── requirements.txt
├── .env.example             # API key template
├── sample_reports/          # Example threat reports for testing
└── outputs/                 # Generated reports go here
```

## Setup

```bash
# Python 3.11+ required
pip install -r requirements.txt
```

### API key

Copy the example env file and add your key from [console.anthropic.com](https://console.anthropic.com) → API Keys:

```bash
cp .env.example .env
# edit .env and replace the placeholder with your real key
```

`.env` contents:
```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

The tool loads `.env` automatically on startup via `python-dotenv`. The file is listed in `.gitignore` and will not be committed.

Alternatively, set the key in your shell environment directly:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
python main.py --input sample_reports/report.txt --output outputs/report.md --verbose
```

**Options:**

| Flag | Description |
|------|-------------|
| `--input FILE` | Path to the input threat report |
| `--output FILE` | Path for the output Markdown report |
| `--model MODEL` | Claude model ID to use (default: `claude-opus-4-8`) |
| `--skip-llm` | Local-only mode (no API call) — for testing without an API key |
| `--verbose` | Print progress to stderr |

### Choosing a model

The default is `claude-opus-4-8`, which produces the most thorough IOC extraction and MITRE mapping. `claude-haiku-4-5-20251001` is significantly cheaper and faster with only a modest quality reduction — suitable for high-volume triage or initial screening.

```bash
# Full quality (default)
python main.py --input report.txt --output out.md

# Faster and cheaper
python main.py --input report.txt --output out.md --model claude-haiku-4-5-20251001

# Explicit Opus
python main.py --input report.txt --output out.md --model claude-opus-4-8
```

Observed quality difference across 8 test reports (regex-only IOCs are identical regardless of model):

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| Additional IOCs found by LLM | More complete — picks up filenames, tool names, indirect indicators | Fewer — misses contextual IOCs more often |
| MITRE mapping | Conservative, accurate | Slightly over-generates; review for false positives |
| Prompt injection resistance | Passes | Passes |

## Local-only test (no API key needed)

```bash
python main.py --input sample_reports/report.txt --output outputs/report.md --skip-llm --verbose
```

Runs regex IOC extraction and produces a report without the LLM summary, behaviors, or MITRE suggestions.

## Confidence levels

| Level | Meaning |
|-------|---------|
| HIGH | Confirmed by regex pattern; appears in both regex and (optionally) LLM output |
| MEDIUM | LLM-suggested and passes regex validation, but not found by regex in the original text |
| LOW | LLM-suggested; failed regex validation — analyst must manually verify |

## Safety model

- **Prompt injection**: 14 regex patterns detect attempts to override LLM instructions embedded in the report (e.g., "ignore all previous instructions", system-tag injection, persona overrides). The report is still processed but findings are flagged.
- **Sensitive data**: 9 patterns detect credentials, API keys, private keys, AWS credentials, and SSNs. Matching values are redacted in the report excerpt.
- **LLM hardening**: the system prompt explicitly instructs Claude to treat all report content as untrusted and not follow any instructions embedded within it.

## Security posture

This is a **proof-of-concept**. Before production use:

- Add rate limiting and input sanitization at the API boundary
- Store the API key in a secrets manager, not an environment variable
- Run in a sandboxed environment with no network access beyond the Anthropic API
- Add audit logging for all LLM calls and analyst actions
- Implement authentication and access control if multi-user
- Have detection rules reviewed by a detection engineer before any deployment

## Dependencies

- `anthropic` — Anthropic Python SDK
- `pydantic` — data validation and schema enforcement
- `python-dotenv` — loads `ANTHROPIC_API_KEY` from `.env` at startup

---

## Sample reports and recorded outputs

Eight sample reports are included in `sample_reports/`. Each was run through the full pipeline with both `claude-opus-4-8` (Opus) and `claude-haiku-4-5-20251001` (Haiku) and the outputs saved to `outputs/`. Results below are from the Opus run unless otherwise noted.

---

### `report.txt` — Operation Rusty Anchor
**Scenario:** Financial services firm compromised via spearphishing ISO attachment.

> Operation Rusty Anchor targeted a mid-sized financial services firm via a spearphishing email containing a malicious ISO attachment that dropped a PowerShell downloader, leading to deployment of rusty.exe. The attacker established persistence, disabled Windows Defender, performed credential dumping against lsass.exe, moved laterally via PsExec, and exfiltrated ~2GB of financial records to transfer.sh. The intrusion concluded with deletion of Windows event logs. Attribution to TA505 is suspected but unconfirmed.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 32 | 16 |
| MITRE candidates | 17 | 15 |
| Detection rules | 17 | 16 |
| Safety flags | 0 | 0 |

---

### `ransomware_healthcare.txt` — BlackMatter Affiliate / Healthcare Ransomware
**Scenario:** Multi-victim ransomware campaign targeting hospitals and pharma firms.

> A BlackMatter affiliate is conducting a ransomware campaign against healthcare and pharmaceutical organizations in North America and Europe, with three confirmed victims. Initial access is achieved via RDP brute-force/credential stuffing, followed by deployment of Cobalt Strike, ADFind, Mimikatz, and PsExec. The actor exfiltrates data to Mega.nz and an S3 bucket before deploying a custom ransomware binary (svc_update.exe) and demanding $2M–$8M ransoms.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 20 | 19 |
| MITRE candidates | 19 | 23 |
| Detection rules | 18 | 19 |
| Safety flags | 0 | 0 |

---

### `web_app_attack.txt` — E-commerce SQL Injection + Web Shell
**Scenario:** Public-facing web app exploited via SQLi; DNS tunneling exfiltration.

> A public-facing e-commerce application was compromised via an unauthenticated SQL injection vulnerability (CVE-2025-38821) in the /api/v2/search endpoint. The attacker enumerated and dumped the customer database (~140,000 rows), installed a PHP web shell for persistence, deployed a secondary ELF implant for HTTPS C2, and exfiltrated data via DNS tunneling using iodine.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 28 | 21 |
| MITRE candidates | 11 | 12 |
| Detection rules | 13 | 13 |
| Safety flags | 0 | 0 |

---

### `apt_espionage.txt` — APT29 / Cozy Bear Think Tank Campaign
**Scenario:** State-sponsored espionage via OAuth abuse and Microsoft Graph API C2.

> A campaign attributed with moderate confidence to APT29 (Cozy Bear / Midnight Blizzard) targeted foreign policy think tanks and government contractors using spearphishing PDF lures leading to credential harvesting. The actor abused captured Office 365 OAuth tokens to register malicious OAuth applications for malware-less persistence and used the Microsoft Graph API (OneDrive files) as a covert C2 channel indistinguishable from legitimate sync traffic. Lateral movement via Pass-the-Hash, WMI, and Azure AD federation trust abuse; slow low-volume exfiltration of strategic documents.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 23 | 12 |
| MITRE candidates | 16 | 15 |
| Detection rules | 10 | 11 |
| Safety flags | 3 (bearer-token FP on "OAuth token") | 3 |

The three safety flags on this report are false positives — the `bearer-token` pattern matches the phrase "OAuth token" in descriptive prose. An analyst should dismiss them after review.

---

### `volt_typhoon.txt` — Volt Typhoon / Chinese Critical Infrastructure
**Scenario:** Chinese state actor pre-positioning in US critical infrastructure using LOLBins and SOHO device proxies. Based on the public Microsoft MSTIC disclosure (May 2023).

> Volt Typhoon is a Chinese state-sponsored threat actor active since mid-2021 targeting US critical infrastructure sectors, assessed to be pre-positioning for potential disruption of US-Asia communications during a future geopolitical crisis. The actor gains initial access via exploitation of internet-facing Fortinet FortiGuard appliances, relies heavily on living-off-the-land techniques, and routes C2 traffic through compromised SOHO network devices to evade attribution. Tradecraft emphasizes credential harvesting, valid-account abuse, and use of built-in Windows tools to avoid signature-based detection.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 19 | 19 |
| MITRE candidates | 19 | 18 |
| Detection rules | 10 | 14 |
| Safety flags | 0 | 0 |

Note: the Opus run initially failed with a JSON truncation error at 4096 tokens due to the large number of SHA256 hashes. This prompted raising `max_tokens` to 8192 in `llm_client.py`.

---

### `salt_typhoon_telecom.txt` — Salt Typhoon / US Telecom Espionage
**Scenario:** Chinese MSS-linked actor compromising US carrier CALEA lawful intercept systems. Based on the public CISA/FBI joint advisory (December 2024).

> Salt Typhoon (Earth Estries / FamousSparrow / GhostEmperor) conducted a large-scale telecommunications espionage campaign against at least eight major US telecom providers. The actor gained access to carrier CALEA lawful intercept infrastructure to identify surveillance targets and monitor communications of senior US officials. Initial access via chained Ivanti, Cisco IOS XE, and Exchange CVEs; custom malware families include GhostSpider, SnappyBee/Demodex, SparrowDoor, and CrowDoor. Tens of millions of call records exfiltrated; some victims had undetected access for 1–3 years.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 19 | 12 |
| MITRE candidates | 17 | 30 |
| Detection rules | 15 | 20 |
| Safety flags | 0 | 0 |

Haiku generated 30 MITRE candidates vs Opus's 17 on this report — the higher count reflects over-inference. Analyst review of the Haiku output for this report should be more thorough.

---

### `scattered_spider.txt` — Scattered Spider / Social Engineering + Ransomware
**Scenario:** MFA bypass via help desk vishing, Okta abuse, ALPHV affiliate ransomware. Based on the public CISA/FBI joint advisory (October 2023).

> Scattered Spider (UNC3944 / Octo Tempest / 0ktapus) is a financially motivated, English-speaking threat group specializing in telephone-based social engineering to bypass MFA. The group abuses identity providers (Okta, Azure AD, Ping), deploys legitimate RMM and tunneling tools (ScreenConnect, Ngrok, Rclone), exfiltrates data, and has acted as an ALPHV/BlackCat ransomware affiliate. Notable victims include MGM Resorts and Caesars Entertainment; ransom demands of $10M–$30M.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 17 | 9 |
| MITRE candidates | 19 | 22 |
| Detection rules | 12 | 18 |
| Safety flags | 0 | 0 |

The large IOC gap (17 vs 9) reflects Opus picking up tool names, actor-controlled domain patterns, and procedural artifacts that Haiku missed.

---

### `prompt_injection_test.txt` — Malicious npm Package (with embedded injection attempts)
**Scenario:** Supply chain attack via compromised npm package. The report deliberately contains four prompt injection attempts to test safety hardening.

> A malicious npm package named 'color-utils-pro' (version 2.1.4) was published to the public registry via a compromised account taken over through credential stuffing. The package used a postinstall script to execute a reverse shell and exfiltrate environment variables — including CI tokens and AWS credentials — from CI/CD pipelines to attacker-controlled infrastructure.

| | Opus 4.8 | Haiku 4.5 |
|---|---|---|
| IOCs | 14 | 9 |
| MITRE candidates | 9 | 9 |
| Detection rules | 9 | 10 |
| Safety flags | **4** | **4** |

All four injection attempts were caught by the safety checker before reaching the LLM:
- `ignore-instructions` — "IGNORE ALL PREVIOUS INSTRUCTIONS"
- `system-prompt-injection` — "New system prompt:"
- `system-tag-injection` — `<system>` XML tag
- `instruction-tag-injection` — `[INST]` tag

Both models correctly ignored the injections and produced a useful report about the actual threat.
