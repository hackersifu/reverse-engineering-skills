# reverse-engineering-skills

A public collection of **agent skills** for **defensive reverse engineering** and malware analysis workflows.

The goal: make common RE tasks more repeatable and easier to operationalize by packaging them as small, composable skills with clear inputs, outputs, and guardrails.

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
|------|----------------|
| **re-ioc-extraction** | Extract and normalize defensive IOCs (domains, IPs, URLs, hashes, mutexes, registry paths, file paths, user agents) from analyst-provided evidence (strings output, logs, RE notes). Produces a traceable IOC table plus a structured list suitable for reporting and detection workflows. |

## Usage

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
