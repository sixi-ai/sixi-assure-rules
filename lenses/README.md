# Lenses

A **lens** re-labels findings that a deterministic rule has already produced. It is data only: no
loader reads `lenses/` in this slice, and nothing here may ever create, suppress or change a
finding (CLAUDE.md §1.2 — *deterministic rules decide*). A lens answers "what does this finding look
like in the vocabulary my security team already uses?", and nothing else.

| File | Maps | Source | Licence |
|---|---|---|---|
| `atlas.yaml` | rule id → MITRE ATLAS technique ids | `atlas-data` release **v2026.09** | Apache-2.0 (© MITRE 2021–2026) |
| `stride.yaml` | rule id → STRIDE categories | none (our own classification) | — |

## Format

```yaml
lens: atlas                 # stable lens id, matches the file name
version: v2026.09           # version of the *source* knowledge base, or of this file when there is none
source: https://…           # where the ids come from; must resolve
licence: Apache-2.0         # licence of the source ids and names
accessed: 2026-09-16        # the day the source was fetched
notes: |                    # free text: what was checked, what was deliberately left out
  …
map:                        # rule id → list of entries; a rule with no confident entry is simply absent
  AI-001:
    - id: AML.T0040         # identifier in the source knowledge base
      name: AI Model Inference API Access   # name exactly as the source spells it
      why: one sentence, in our words, saying why this structural finding enables that technique
```

`stride.yaml` uses the same header with a `categories:` map of the six letters and a `map:` of rule id
→ letters (`S T R I D E`), ordered as in the STRIDE acronym.

## Rules of use

1. **Never a finding source.** A lens entry may appear beside a finding that a rule already produced,
   never instead of one. An architecture that maps to twelve ATLAS techniques has no findings unless a
   rule fired.
2. **No regulatory weight.** ATLAS is a threat knowledge base and STRIDE is a taxonomy; neither is a
   clause. Regulatory statements keep citing `REGIME:DOC:REF` from `corpus/` (CLAUDE.md §1.4).
3. **Only identifiers that exist.** Every ATLAS id in `atlas.yaml` was read out of the
   `ATLAS-2026.09.yaml` release asset on 2026-09-16. If an id cannot be confirmed it is left out and
   said so in `notes:` — an invented technique id is worse than an unmapped rule.
4. **Coverage is partial on purpose.** Rules whose structural fact has no clear technique are absent
   from `map:`. Absence means "not mapped", never "not a risk".
5. **Wording.** A lens never claims an architecture is secure or approved, and never asserts a
   regulatory outcome; it names the attack technique or threat category a drawn weakness enables.
