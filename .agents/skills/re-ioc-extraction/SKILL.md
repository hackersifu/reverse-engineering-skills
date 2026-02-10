---
name: re-ioc-extraction
description: Extract and normalize defensive IOCs (domains, IPs, URLs, file hashes, mutexes, registry paths, file paths, user agents) from analyst-provided evidence such as strings output, sandbox logs, network logs, or reverse engineering notes. Use when the user wants IOCs for detection, blocking, hunting, or reporting.
---

# re-ioc-extraction

## Purpose
Produce a complete, **defensive IOC set** from analyst-provided evidence and present it in:
1) a Markdown IOC table, and  
2) a structured YAML list,  
with **traceable evidence only** (no guessing, no enrichment, no validation).

## Inputs expected
Provide at least one of the following (more is better):
- `strings` output (ASCII and/or UTF-16)
- sandbox / EDR / detonation logs (process, file, registry, network)
- packet/proxy/DNS logs or extracted HTTP requests
- reverse engineering notes (imports, APIs, decompiled snippets, paths, config blobs)
- known hashes from a trusted source

If evidence is missing, the skill must still produce output for what is present and clearly note gaps.

## Optional evidence generation (static only)
If the user asks for help generating evidence locally (or you are explicitly allowed to run commands), prefer **small, single-purpose commands** that are hard to break and easy to copy/paste.

### Command hygiene (important)
- Prefer **one pattern per command** over long one-liners with many quoted arguments.
- Avoid complex nested quotes. If a command needs heavy quoting, break it into multiple commands.
- If a combined command fails (e.g., quoting/EOF errors), rerun as **several simple commands** and proceed.

### Tool availability check (recommended)
```bash
command -v file strings sha256sum sha1sum md5sum capa jq || true
```

### file (type/format context)
```bash
file "<sample>"
```

### hashes (for reporting / dedupe)
```bash
sha256sum "<sample>"
sha1sum "<sample>"
md5sum "<sample>"
```

### strings (baseline)
```bash
strings -a "<sample>" | head -n 2000
```

### strings (UTF-16 / wide strings on Windows malware)
```bash
strings -el "<sample>" | head -n 2000
```

### Searching extracted strings safely (recommended pattern)
First save strings to a file, then search with **one pattern per command**:
```bash
strings -a "<sample>" > /tmp/sample.strings.txt
strings -el "<sample>" > /tmp/sample.strings.utf16.txt

rg -n -F "http://" /tmp/sample.strings.txt
rg -n -F "https://" /tmp/sample.strings.txt
rg -n -F ".onion" /tmp/sample.strings.txt
rg -n -F "HKEY_" /tmp/sample.strings.utf16.txt
rg -n -F "CurrentVersion\Run" /tmp/sample.strings.utf16.txt
```

### capa (use when available; degrade gracefully)
Use capa only as **supporting static context** (capabilities, packer/obfuscation hints). It does not directly produce IOCs.
- If capa fails due to rule/signature mismatches, note it and continue with the evidence you do have.
- If you have to pin rules, do so explicitly and record the rules version used in notes.

## Non-negotiable rules
1) **No hallucinations:** only output indicators explicitly present in the evidence.
2) If incomplete/ambiguous (e.g., `hxxp://`, partial domains, truncated hashes), label **candidate / incomplete** and state what’s missing.
3) **No live validation:** do not resolve domains, visit URLs, or test infrastructure. Extraction and normalization only.
4) Every IOC must be **traceable**: include a **verbatim** evidence snippet (exact line or tight excerpt) and the source artifact (strings/log/notes).
5) **Stay on scope:** do not inspect unrelated environment files (shell dotfiles, configs) unless explicitly requested. Focus on the sample and provided evidence.
6) **Do not “upgrade” indicators:** do not infer C2/persistence/stealer behavior into network IOCs unless the indicator values are present. Behavioral assessment is optional notes only.

## IOC types to extract
Extract only what is present in evidence. Common types include:
- Hashes: MD5 / SHA1 / SHA256
- Network: domains/subdomains, IPs (v4/v6), URLs, URI paths, ports, SNI/Host headers if present
- Email addresses (if present)
- File system: dropped file names, file paths
- Windows persistence: registry keys/values, services, scheduled task names/paths (only if values are present)
- Mutex names
- User-Agent strings
- Process names / command lines (only if explicitly present)
- Certificates/keys: subjects, thumbprints, public keys (only if explicitly present)

## Normalization rules
- Domains: lowercase, strip surrounding punctuation, keep subdomains
- URLs: preserve as-seen; if obfuscated (`hxxp`), include both obfuscated and normalized forms
- IPs: normalize formatting; preserve IPv6
- Hashes: lowercase; do not “fix” length or guess missing characters
- Paths/registry: preserve exactly as provided; do not guess missing segments
- De-obfuscation: only apply mechanical transforms that are explicitly reversible and obvious (e.g., `hxxp`→`http`). Do not decode custom encodings unless the decoded value is shown in evidence.

## Confidence labels
Use a consistent, limited vocabulary:
- **confirmed**: directly observed in authoritative output (hash tool output, explicit log lines)
- **high / medium / low**: observed in evidence but context quality varies (e.g., noisy logs, partial correlation)
- **contextual**: value is present but not inherently malicious (e.g., PDB path, product name, benign-looking file name)
- **candidate**: looks like an IOC but may be incomplete/obfuscated/ambiguous
- **incomplete**: truncated or partial value (state what is missing)

## Output (always produce both)
### A) IOC table (Markdown)
Include columns:
- Type
- Indicator
- Confidence
- Context (short)
- Evidence (verbatim snippet + where it came from)

Rules:
- One indicator per row.
- Evidence must be an **exact line or tight excerpt** containing the indicator (do not paraphrase).
- If the same IOC appears in multiple sources, include the best/most authoritative snippet, and optionally list a second snippet in the context.

### B) Structured IOC list (YAML)
#### Schema (strict)
Top-level keys (include only those that have entries):
- `hashes`
- `network`
- `file_paths`
- `file_names`
- `process_names`
- `registry`
- `mutexes`
- `user_agents`
- `emails`
- `certificates`
- `notes` (optional)
- `static_risk_notes` (optional; see below)

Each list entry **must** include:
- `value` (string)
- `confidence` (one of: confirmed, high, medium, low, contextual, candidate, incomplete)
- `source` (short label such as: "hash command output", "strings output", "UTF-16 strings output", "sandbox log", "network log", "RE notes")
- `evidence_snippet` (verbatim line/excerpt containing the value)

Additional required fields by type:
- `hashes[]`: `algorithm` (md5|sha1|sha256)
- `network[]`: `kind` (domain|ipv4|ipv6|url|uri_path|port|sni|host_header)  
  - If `kind: port`, `value` must be a string like `"tcp/443"` or `"udp/53"` when protocol is known; otherwise `"port/443"`.
- `registry[]`: `kind` (key|value|data) when known
- `certificates[]`: `kind` (subject|thumbprint|public_key) when known

Example (shape only):
```yaml
hashes:
  - value: "..."
    algorithm: "sha256"
    confidence: "confirmed"
    source: "hash command output"
    evidence_snippet: "sha256sum sample -> ..."

network:
  - kind: "domain"
    value: "example.com"
    confidence: "high"
    source: "sandbox log"
    evidence_snippet: "DNS query: example.com"
```

## Optional: static risk notes (do not invent IOCs)
If the user asks “is it malicious?” you may include a short `static_risk_notes` section in YAML (and/or a short paragraph after the IOC table) that:
- cites the exact static evidence used (e.g., packing/obfuscation signs, capa capability names, suspicious API surface),
- avoids definitive attribution,
- never manufactures missing IOCs.

Keep it brief and operational (what defenders should treat as risky and why).

## Minimal clarification questions (only if required; max 1–3)
Ask only if needed to avoid incorrect extraction:
- “Do you want only **confirmed** IOCs, or include **candidate/contextual** values too?”
- “Is this evidence from **strings only** or do you have **sandbox/network logs** as well?”
- “Do you want output optimized for a specific consumer (SIEM rule, EDR blocklist, report)?”

## Happy path example (regression anchor)
### Example evidence (input)
```
sha256sum sample.exe -> 1111111111111111111111111111111111111111111111111111111111111111
sha1sum sample.exe   -> 2222222222222222222222222222222222222222
md5sum sample.exe    -> 33333333333333333333333333333333

strings:
... hxxp://BadDomain[.]com/path/index.php
... User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
... D:\Build\proj\bin\Release\sample.pdb
```

### Expected IOC table (output)
| Type | Indicator | Confidence | Context | Evidence |
|---|---|---|---|---|
| sha256 | 1111111111111111111111111111111111111111111111111111111111111111 | confirmed | Sample hash | `sha256sum sample.exe -> 1111...1111` |
| sha1 | 2222222222222222222222222222222222222222 | confirmed | Sample hash | `sha1sum sample.exe   -> 2222...2222` |
| md5 | 33333333333333333333333333333333 | confirmed | Sample hash | `md5sum sample.exe    -> 3333...3333` |
| url (obfuscated) | hxxp://BadDomain[.]com/path/index.php | candidate | Obfuscated URL in strings | `... hxxp://BadDomain[.]com/path/index.php` |
| url | http://baddomain.com/path/index.php | candidate | Normalized from hxxp + [.] | `... hxxp://BadDomain[.]com/path/index.php` |
| user_agent | Mozilla/5.0 (Windows NT 10.0; Win64; x64) | contextual | UA string in strings | `... User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)` |
| file_path | D:\Build\proj\bin\Release\sample.pdb | contextual | Embedded build/debug path | `... D:\Build\proj\bin\Release\sample.pdb` |

### Expected YAML (output)
```yaml
hashes:
  - value: "1111111111111111111111111111111111111111111111111111111111111111"
    algorithm: "sha256"
    confidence: "confirmed"
    source: "hash command output"
    evidence_snippet: "sha256sum sample.exe -> 1111111111111111111111111111111111111111111111111111111111111111"
  - value: "2222222222222222222222222222222222222222"
    algorithm: "sha1"
    confidence: "confirmed"
    source: "hash command output"
    evidence_snippet: "sha1sum sample.exe   -> 2222222222222222222222222222222222222222"
  - value: "33333333333333333333333333333333"
    algorithm: "md5"
    confidence: "confirmed"
    source: "hash command output"
    evidence_snippet: "md5sum sample.exe    -> 33333333333333333333333333333333"

network:
  - kind: "url"
    value: "hxxp://BadDomain[.]com/path/index.php"
    confidence: "candidate"
    source: "strings output"
    evidence_snippet: "... hxxp://BadDomain[.]com/path/index.php"
  - kind: "url"
    value: "http://baddomain.com/path/index.php"
    confidence: "candidate"
    source: "strings output"
    evidence_snippet: "... hxxp://BadDomain[.]com/path/index.php"

user_agents:
  - value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    confidence: "contextual"
    source: "strings output"
    evidence_snippet: "... User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

file_paths:
  - value: "D:\\Build\\proj\\bin\\Release\\sample.pdb"
    confidence: "contextual"
    source: "strings output"
    evidence_snippet: "... D:\Build\proj\bin\Release\sample.pdb"
```

## Definition of done
- Every indicator in the table is present in the evidence and has a verbatim snippet.
- YAML conforms to the schema and uses only allowed confidence labels.
- Normalization is applied without guessing missing values.
- No live validation/enrichment was performed.
- If the user asked about maliciousness, any risk notes are brief, evidence-cited, and do not invent IOCs.
