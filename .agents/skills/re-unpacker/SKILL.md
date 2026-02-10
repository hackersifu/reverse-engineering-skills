---
name: re-unpacker
description: Identify packing/obfuscation indicators and guide a safe, analyst-in-the-loop unpacking workflow to recover a higher-fidelity sample for defensive analysis. Produces an unpacking plan and an unpacking report with traceable evidence.
---

# re-unpacker

## Purpose
Help a defender determine whether a sample appears packed/obfuscated and, if so, produce a **safe, repeatable unpacking plan** (static-first, optional dynamic only in a controlled sandbox) to recover a higher-fidelity artifact (e.g., dumped PE section(s) / unpacked executable) for downstream analysis and detection.

This skill is designed for **incident response, malware triage, and reverse engineering** workflows.

## When to use
Use when you have:
- A suspicious PE/ELF/Mach-O that looks packed (few readable strings, anomalous sections, entropy spikes).
- A “known” malware family sample that’s heavily obfuscated and you need a cleaner artifact for strings/capa/yara.
- A sandbox run indicating in-memory unpacking/decryption prior to behavior.

## When NOT to use
- If you cannot run the sample safely (no sandbox/VM, no containment) and unpacking requires execution.
- If the request is to create/modify malware, evade detection, or otherwise enable wrongdoing.

## Inputs expected
Provide at least one of:
- **File metadata**: `file` output, hashes, size, compile timestamp (if present).
- **Static triage outputs**: section table (`objdump -h`/`lief`/`pefile`), imports (`objdump -x`, `peframe`), entropy results (if you have them), strings (ASCII/UTF-16), packer signatures (Detect It Easy/PEiD/peframe), capa output.
- **Dynamic/sandbox notes (optional)**: process tree, API calls, memory map, module loads, “RWX” allocations, unpacking/dump events, or EDR telemetry.

If you want the skill to guide evidence generation, say so and include your environment constraints (OS, tools available, whether you can run a VM/sandbox).

## Non‑negotiables (guardrails)
- **Defensive-only**: do not provide instructions intended to enable malware creation, stealth, or evasion.
- **No blind execution**: never instruct running unknown samples on a host system. If dynamic steps are necessary, require a **controlled sandbox/VM** and minimal-risk configuration.
- **Evidence-first**: claims about “packed”, “UPX”, “Themida”, etc. must be tied to provided evidence (tool output, section names, signatures, entropy, imports, runtime telemetry).
- **Do not invent artifacts**: if you did not see a dump/unpacked file, do not claim you produced one.
- **Command hygiene**: prefer small, single-purpose commands; avoid long one-liners that are likely to fail on quoting.

## Output requirements
Return:
1) **Packing assessment summary** (1–6 bullets) with cited evidence excerpts.
2) **Unpacking plan** (step-by-step) in priority order:
   - Static-only steps first
   - Dynamic/sandbox steps only if needed
3) **Unpacking report** (template filled with what we know), including:
   - hashes of original sample
   - artifacts produced (if any) + hashes + how they were produced
   - environment assumptions and safety notes
4) **Next-step recommendations** (what to do with the unpacked artifact: strings/capa/yara/IOC extraction)

### Confidence vocabulary
Use one of: `confirmed | high | medium | low | contextual`
- `confirmed`: direct tool output or direct observation (e.g., “UPX!” signature, a successful dump hash).
- `high/medium/low`: reasoned judgment with supporting evidence; note limitations.
- `contextual`: relevant but not diagnostic (e.g., suspicious filename).

## Procedure

### Step 1 — Establish a safe baseline (always)
- Confirm you are working in a **non-production** environment.
- Identify the sample and compute hashes.

**Preferred evidence (paste outputs):**
- `sha256sum "<sample>" && sha1sum "<sample>" && md5sum "<sample>"`
- `file "<sample>"`

### Step 2 — Static triage for packing indicators
Look for **multiple independent signals**:

**A) Strings**
- Very few readable strings or mostly garbage
- Short repetitive fragments
- Encrypted/config blobs without surrounding context

Commands (Linux):
- `strings -a "<sample>" | head -n 200`
- `strings -el "<sample>" | head -n 200`  (UTF-16)

**B) Sections**
- Unusual section names (random-looking, single huge section, missing typical sections)
- Very small import table, tiny `.text`, huge `.data`/custom section
- High entropy sections (if available)

Commands:
- `objdump -h "<sample>" | head -n 200`
- `objdump -x "<sample>" | head -n 260`

**C) Imports & loader behavior hints**
- Minimal imports; heavy reliance on `LoadLibrary/GetProcAddress` (Windows) or `dlsym` (Linux)
- Presence of anti-debug/anti-VM APIs (contextual, not definitive)

**D) Signature tooling (optional)**
If you have them: Detect It Easy (DIE), peframe, floss, capa.
- If you paste outputs, I will interpret them and cite them.

### Step 3 — Decide the unpacking approach (static-first)
#### 3.1 If it looks like a known packer with a clean static unpack path
Example: UPX, some self-extracting formats.

- Prefer **vendor/official unpack tool** or well-known offline unpack method.
- Validate success by comparing:
  - section structure changes
  - strings increase
  - imports become more realistic
  - hashes change (expected)

> If the evidence indicates UPX specifically, I may suggest `upx -d` in a controlled environment, but I will not assume UPX without evidence.

#### 3.2 If static unpack is not feasible → dynamic/sandbox-only path
This path requires:
- an isolated VM/sandbox snapshot you can revert
- no credentials, no sensitive mounts, no production network
- ideally an instrumented sandbox (e.g., CAPE/any.run/VM + monitoring)

Dynamic unpacking signals to look for:
- RWX memory allocations followed by execution
- decrypted code pages
- “unpacking stubs” then a jump to a new region
- child process injection / hollowing (Windows)

**Dynamic steps (high level, defensive)**
- Run in sandbox with monitoring enabled.
- Identify when the sample transitions from stub → payload.
- Dump memory region(s) containing the payload **only if your tooling supports it safely**.
- Extract dumped PE and validate with offline tooling.

> I will not provide instructions to disable defenses, bypass EDR, or evade analysis.

### Step 4 — Validate unpacking success (evidence-driven)
Success criteria (at least two):
- Readable strings meaningfully increase (and look semantically relevant).
- Import table becomes richer/more realistic.
- capa hits become more specific / higher coverage.
- Decompression/decryption artifacts observed and dumped.

### Step 5 — Produce artifacts + document provenance
If you produced an unpacked/dumped artifact, capture:
- where it came from (file path, memory dump details, tool output)
- hashes
- how to reproduce

## Unpacking report format (what I will output)

### Packing assessment
- **Verdict**: packed/likely packed/unclear
- **Confidence**: <value>
- **Why (evidence excerpts)**:
  - <excerpt 1>
  - <excerpt 2>

### Unpacking plan (prioritized)
1. <static step> (expected outcome, validation check)
2. <static step> ...
3. <dynamic step (sandbox only)> ...

### Artifacts
- **Original sample**
  - sha256: ...
  - sha1: ...
  - md5: ...
  - notes: ...
- **Unpacked/dumped artifacts (if any)**
  - path: ...
  - sha256: ...
  - provenance: ...
  - validation: ...

### Next steps
- Run `re-ioc-extraction` on strings/logs from the unpacked artifact.
- Run capa/yara on unpacked artifact and compare deltas vs original.
- Extract config (if present) using static methods where possible.

## Definition of done
- A defensible packing assessment with evidence excerpts.
- A prioritized unpacking plan that respects safety constraints.
- If an unpacked artifact exists: hashes + provenance + validation notes.
- Clear next steps for downstream defensive analysis.
