# Security policy

## Reporting a vulnerability

Email **contact@sixi.ai** with `SECURITY` in the subject. Please do not open a public issue, a
discussion or a pull request for a vulnerability.

Include what you have: the affected file or command, the version or commit, a model or pack that
reproduces the behaviour, and what you think the impact is. If you would like a reply encrypted,
say so in the first message and we will arrange a key.

**What to expect**: acknowledgement within 3 working days, an assessment with a planned fix date
within 10 working days, and credit in the release notes if you want it. We will tell you when the
fix ships. Please give us 90 days before publishing, and less if the issue is already public or
being exploited — we will not ask you to wait longer than is useful.

We do not run a paid bounty programme.

## Scope

In scope, in this repository:

- The Go packages: `model/` (schema validation and invariants), `rules/` (pack loading, the CEL
  environment, the engine), `secretguard/`, `corpus/`, `schema/` and the two commands.
- Anything that lets untrusted input escape its bounds: a crafted model that causes unbounded
  memory or CPU use despite the per-rule cost and time limits, a pack or policy file that escapes
  the CEL environment, a path that reads a file outside the directories it was given, a JSON Patch
  template that writes where it should not.
- A defect in `secretguard/` that lets a credential-shaped string through the model write path, or
  that echoes the value it detected.
- A rule or clause record whose content could mislead a reader about a legal obligation. Report it
  here rather than in public if you think it is exploitable; otherwise an issue is fine.

Out of scope here: the hosted product at https://sixi.ai and its infrastructure (report those to
the same address, they are handled under a separate policy), findings that require an attacker to
already control the machine running the command, and the synthetic credential-shaped fixtures in
`secretguard/testdata/` — those are test vectors, are documented in `secretguard/README.md`, and
are not and never were real credentials.

## Threat model in one paragraph

Everything this engine reads is untrusted: architecture models, imported diagrams, rule packs and
policy files supplied by an operator. Models are validated against the JSON Schema and the
invariants before anything else touches them, and the secret guard runs first of all. The CEL
environment is closed: no network, no file access, no clock; every rule is cost-limited and
time-limited, and a rule that fails is reported as a rule error rather than being silently dropped.
The engine emits no model content into logs. Findings are produced by rules only — there is no
model, no heuristic and no language model in this repository.

## Supported versions

The `main` branch is supported. Fixes land there and are mirrored from the product repository.

Contact: **contact@sixi.ai**
