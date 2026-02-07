---
name: re-ioc-extraction
description: Extract and normalize defensive IOCs (domains, IPs, URLs, file hashes, mutexes, registry paths, file paths, user agents) from analyst-provided evidence such as strings output, sandbox logs, network logs, or reverse engineering notes. Use when the user wants IOCs for detection, blocking, hunting, or reporting.
---

# re-ioc-extraction

## Purpose
Produce a clean, defensible IOC set from provided evidence **without inventing indicators**. This skill supports defensive workflows (detection engineering, IR reporting, hunting).

## Inputs expected
The user should provide one or more of:
- Strings output (e.g., `strings`, FLOSS, extracted config)
- Sandbox / execution logs
- Network logs (DNS/HTTP/proxy, PCAP summaries, Zeek)
- Reverse engineering notes (observed constants, decrypted config, function summaries)
- Hashes already computed by the analyst

If no evidence is provided, ask for the evidence source(s) before proceeding.

## Optional evidence generation (static only)
If the user has a local sample and wants help generating evidence for IOC extraction, suggest static commands and ask them to paste the outputs back into the chat. Do not execute the sample.

### Tool availability check (recommended)
Before suggesting commands, check what is installed:

- `command -v file strings sha256sum sha1sum md5sum capa || true`

If a tool is missing:
- Prefer installing the missing tool(s) if the environment allows it.
- Otherwise use the fallbacks below.

Note (AWS CloudShell): CloudShell uses Amazon Linux 2023 and the package manager is `dnf`.
If `strings`/`objdump` are missing, installing `binutils` typically provides them:
- `sudo dnf install -y binutils`

### strings (baseline)
Goal: extract embedded strings that may include URLs/domains/paths/registry keys.

- macOS/Linux:
  - `strings -a "<sample>" | head -n 2000`
- Windows (Sysinternals Strings):
  - `strings.exe -nobanner -accepteula "<sample>"`

Fallback if `strings` is not available (targeted search):
- `rg -a -n "(http|https|hxxp|[0-9]{1,3}(\\.[0-9]{1,3}){3}|[A-Za-z0-9.-]+\\.[A-Za-z]{2,}|Software\\\\|HKEY_|User-Agent:)" "<sample>"`

Tip: If output is large, ask the user to paste:
- the top N lines, and
- any lines around suspicious hits (URLs/domains/registry paths).

### file (type/format context)
Goal: capture file type (PE/ELF/script), which helps interpret strings and other artifacts.

- macOS/Linux:
  - `file "<sample>"`

Note: `file` identifies format/type; it does **not** compute hashes.

### hashes (for reporting / dedupe)
Goal: compute MD5/SHA1/SHA256 (as available) for an artifact table.

- macOS:
  - `shasum -a 256 "<sample>"`
  - `shasum -a 1 "<sample>"`
  - `md5 "<sample>"`
- Linux:
  - `sha256sum "<sample>"`
  - `sha1sum "<sample>"`
  - `md5sum "<sample>"`
- Windows (PowerShell):
  - `Get-FileHash "<sample>" -Algorithm SHA256`
  - `Get-FileHash "<sample>" -Algorithm SHA1`
  - `Get-FileHash "<sample>" -Algorithm MD5`
- Windows (cmd):
  - `certutil -hashfile "<sample>" SHA256`
  - `certutil -hashfile "<sample>" SHA1`
  - `certutil -hashfile "<sample>" MD5`

### capa (required *when available*)
Goal: get static capability classification (persistence, crypto, C2 patterns, etc.) that may provide context for extraction.
If `capa` is installed, **attempt capa and include its output as evidence/context**.

**Rule-set requirement:** capa typically needs a rule set (e.g., `capa-rules`) provided via `-r`. :contentReference[oaicite:1]{index=1}

1) Determine rules path (prefer in this order):
- If `$CAPA_RULES_DIR` is set and exists, use it.
- Else if `./capa-rules` exists, use it.
- Else if `~/capa-rules` exists, use it.
- Else: instruct the user to obtain the rules repo and re-run (do not proceed with capa without rules):
  - `git clone --depth 1 https://github.com/mandiant/capa-rules.git ~/capa-rules` :contentReference[oaicite:2]{index=2}

2) Run capa with JSON output:
- `capa -r "<rules_dir>" -j "<sample>"`

3) If capa errors (missing rules, unsupported format, etc.):
- capture and include the exact error text as evidence
- continue IOC extraction from other evidence sources (strings/hashes/file), but **note capa was unavailable**.

### What to do with outputs
Ask the user to paste one or more outputs (strings, file type, hashes, capa) as evidence.
Then proceed with extraction per the non-negotiable rules and output:
- IOC table (Markdown)
- Structured IOC list (YAML)

## Non-negotiable rules
1) **No hallucinations:** only output indicators explicitly present in the evidence.
2) If incomplete/ambiguous (e.g., `hxxp://`, partial domains, truncated hashes), label **candidate / incomplete** and state what’s missing.
3) **No live validation:** do not resolve domains, visit URLs, or test infrastructure. Extraction and normalization only.
4) Every IOC must be **traceable**: include a short evidence snippet and the source (strings/log/notes).
5) **Stay on scope:** do not inspect unrelated environment files (shell dotfiles, configs) unless explicitly requested. Focus on the sample and provided evidence.

## IOC types to extract
- Hashes: MD5 / SHA1 / SHA256
- Network: domains/subdomains, IPs (v4/v6), URLs, URI paths, ports, SNI/Host if present
- Email addresses (if present)
- File system: dropped file names, file paths
- Windows persistence: registry keys/values, services, scheduled tasks (names/paths if present)
- Mutex names
- User-Agent strings
- Process names / command lines (only if explicitly present)
- Certificates/keys (subjects/thumbprints/public keys) if explicitly present

## Normalization rules
- Domains: lowercase, strip surrounding punctuation, keep subdomains
- URLs: preserve as-seen; if obfuscated (`hxxp`), include both obfuscated and normalized forms
- IPs: normalize formatting; preserve IPv6
- Hashes: lowercase; do not “fix” length or guess missing characters
- Paths/registry: preserve exactly as provided; do not guess missing segments
- De-duplicate values but keep distinct contexts in evidence notes

## Confidence labels
- **confirmed**: complete, unambiguous indicator
- **candidate**: likely relevant but incomplete/templated/ambiguous
- **contextual**: useful hunting context but not an indicator by itself (use sparingly)

Guidance:
- If an indicator appears only in license text, vendor credits, documentation, or generic reference strings (e.g., "Licensed to...", "Copyright...", vendor URLs),
  prefer **contextual** unless corroborated by execution/network/config evidence.

## Output (always produce both)
### A) IOC table (Markdown)
Columns:
- Type
- Indicator
- Confidence
- Context (short phrase)
- Evidence (short snippet)

Formatting rules:
- Keep each table row on a single line (no embedded newlines in cells).
- Truncate Evidence to ~120 characters (append `…`) if needed.
- Escape `|` characters in Evidence/Context as `\|`.

### B) Structured IOC list (YAML)
Group by type; each entry includes:
- value
- confidence
- source
- evidence_snippet

## Minimal clarification questions (only if required; max 1–3)
- Which evidence source is authoritative if they conflict (strings vs sandbox vs notes)?
- Do you want output optimized for a target (blocklist, SIEM query, report appendix)?
- Keep obfuscated forms only, or include both obfuscated + normalized?

## Definition of done
- Every IOC is traceable to evidence (source + snippet).
- No invented indicators.
- Deduped + normalized + confidence-labeled.
- Both table + YAML produced.
