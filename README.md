# reverse-engineering-skills

A public collection of **agent skills** for **defensive reverse engineering** and malware analysis workflows.

The goal: make common RE tasks more repeatable and easier to operationalize by packaging them as small, composable skills with clear inputs, outputs, and guardrails.

## Prerequisites (Codex users)

If you plan to use these skills with **OpenAI Codex**, you’ll need one of the supported Codex clients:

- **Codex CLI** (terminal): https://developers.openai.com/codex/cli/
- **Codex app** (desktop): https://developers.openai.com/codex/app/
- (Optional overview) Codex quickstart: https://developers.openai.com/codex/quickstart/

Codex discovers skills from folders like:

    .agents/skills/<skill-name>/SKILL.md

Skills documentation (how discovery + loading works):  
https://developers.openai.com/codex/skills/

Note: if you add or update skills and they don’t appear in Codex, restart the Codex client you’re using (CLI session, app, or IDE).


## Installation

### Use in a project (recommended)

Copy or vendor this repo’s skills into the repository where you want to use them:

    your-project/
      .agents/
        skills/
          re-ioc-extraction/
            SKILL.md

If you prefer, you can also add this repo as a submodule and copy/symlink specific skill folders into `.agents/skills`.

### Use globally (optional)

If your agent environment supports a user-level skills directory, you can symlink individual skill folders into your global skills path (location varies by tool/OS).

Tip: If you’re unsure, start with the project-local approach. It’s the easiest to share and the easiest to reason about.

## Skill layout

Skills in this repo live under:

    .agents/skills/<skill-name>/SKILL.md

Each skill folder is meant to be standalone and may also include optional supporting material (examples, references, scripts) as the collection grows.

## Available skills

### Reverse engineering

| Skill | What it’s for |
| --- | --- |
| **re-ioc-extraction** | Extract and normalize defensive IOCs (domains, IPs, URLs, hashes, mutexes, registry paths, file paths, user agents) from analyst-provided evidence (strings output, logs, RE notes). Produces a traceable IOC table plus a structured list suitable for reporting and detection workflows. |

## Usage via LLM directly (no Codex required)

You can test a skill with ChatGPT (or any LLM) even without Codex.

Important: a chat model cannot read files from your local disk. To “point to the skill”, you must either:
- paste the contents of the skill’s `SKILL.md` into the chat, or
- provide a link to the `SKILL.md` file in this repo (and use a model/tool that can open links).

### Quick test: re-ioc-extraction
Skill file: [re-ioc-extraction](./.agents/skills/re-ioc-extraction/SKILL.md)


1) Open the skill file:
   - `.agents/skills/re-ioc-extraction/SKILL.md`

2) Paste the **entire** `SKILL.md` contents into your chat (this is the skill).  
   The model cannot read your local `.agents/...` path.

3) Then paste the prompt below.

#### Proposed prompt (normal evidence case)

Follow the instructions in the skill text above.
Extract IOCs from this evidence and output:
1) a Markdown table (Type, Indicator, Confidence, Context, Evidence)
2) a YAML list grouped by type

Evidence (synthetic placeholders — do not invent values):
- URL: <url-placeholder>
- Domain: <domain-placeholder>
- IP: <ip-placeholder>
- Hash: <hash-placeholder>
- Registry key/value: <registry-placeholder>
- File path: <file-path-placeholder>
- Mutex: <mutex-placeholder>

Rules for this test:
- Do not create or guess any indicator values.
- Only classify what is explicitly present in the evidence placeholders above.

#### Proposed prompts (additional quick checks)

**No evidence provided (should ask for evidence):**
Follow the instructions in the skill text above.
Extract IOCs.

**Partial / ambiguous indicators (should label candidate / incomplete and not “complete” them):**
Follow the instructions in the skill text above.
Extract IOCs from this evidence and output the table + YAML.

Evidence:
- hxxps://<partial-domain-placeholder>
- <truncated-hash-placeholder>
- Software\\Microsoft\\Windows\\CurrentVersion\\Run\\


## Usage via agent tooling (Codex/other)

Most agent systems will choose a skill based on the request and the skill’s metadata. You can also invoke it explicitly, for example:

- Use **re-ioc-extraction** on this FLOSS output and produce a YAML list for hunting.
- Extract IOCs from these sandbox logs; label confirmed vs candidate; include evidence snippets.

## Scope and safety

This repo is oriented toward **defensive** and **analyst-in-the-loop** work:

- Skills should be evidence-driven and produce outputs that are easy to validate.
- Skills should avoid inventing indicators or “filling in gaps” with guesses.
- Skills should not include instructions intended to enable wrongdoing.

If you find a place where a skill’s wording could be misused, please open an issue. PRs are also welcome.

## Contributing

Issues and PRs welcome. Helpful contributions include:

- New skills with narrow scope and consistent output formats
- Synthetic or sanitized examples and expected outputs
- Improvements to normalization rules and evidence traceability

Guidelines:

- Keep skills small and composable (prefer multiple focused skills over one mega skill)
- Include “when to use / when not to use” cues in the skill description
- Include a definition of done (what success looks like)

## License

MIT (see `LICENSE`).
