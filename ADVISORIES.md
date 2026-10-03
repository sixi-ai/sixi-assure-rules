# Rule-pack advisories

A defect in a published rule pack is disclosed, not silently fixed. `advisories.json` at the root of this repository
lists every advisory against a published pack version. It is synced from the Sixi Assure product repository
(`rules/advisories.json`, by `scripts/sync-public-rules.sh`), where the schema is specified in `rules/README.md`
§Advisories and a test (`rules/advisories_test.go`, synced here too) validates the file: every advisory names a pack
of `packs/` and rules that exist in that pack, the dates parse, and the wording assesses and evidences. The list is
empty today and **signed later**: `signature` stays `null` until per-organisation signing ships; do not treat an
unsigned list as authoritative.

## Schema (`sixi-assure/rule-advisories/v1`)

| Field | Type | Rule |
|---|---|---|
| `schema` | string | `sixi-assure/rule-advisories/v1` |
| `updated` | date | `YYYY-MM-DD`, not before the newest `published` |
| `signature` | string or null | `null` until signing ships; then a detached signature over the canonical JSON of `advisories` |
| `advisories[].advisory_id` | string | `SAA-YYYY-NNN`, unique, never reused |
| `advisories[].pack` | string | a pack name of `packs/<pack>.yaml` |
| `advisories[].pack_version` | string | `MAJOR.MINOR.PATCH`, the published version affected; one advisory per affected version |
| `advisories[].affected_rules[]` | string[] | rule ids (`^[A-Z]{2,5}-[0-9]{3}$`) that exist in that pack, at least one |
| `advisories[].nature` | enum | `false_negative` · `false_positive` · `wrong_citation` · `wrong_severity` · `wrong_patch` |
| `advisories[].published` | date | `YYYY-MM-DD` |
| `advisories[].summary` | string | ≤ 300 characters, plain text; never *certifies*, *guarantees* or *proves* |
| `advisories[].replacement_pack_version` | string or null | the version that corrects it; `null` while no fix is published |

Entries are appended, never edited in place; a correction is a new advisory that names the earlier id in its summary.
A finding produced by `assure-check` or `assure-eval` is a statement **as of the pack and corpus version** it ran
with; an advisory tells you which findings to re-read. To report a suspected rule defect, follow `SECURITY.md`.

## What the verifier does with it (wave 2, docs/18 WS-J J4 second half)

The offline bundle verifier (docs/18 WS-A A4/A5) will read `advisories.json` beside a bundle and:

| Step | Behaviour |
|---|---|
| Signature | with `signature` present, verify it against the published key before reading a single entry; with `signature: null`, report `advisories: unsigned` and continue — the list informs, it does not decide |
| Match | for each advisory whose `pack` and `pack_version` equal a pack pinned in the bundle's manifest, list the `affected_rules` that produced findings in the bundle and the ones that produced none (a `false_negative` matters most when the rule was silent) |
| Verdict | the bundle's integrity verdict is unchanged — an advisory does not make a hash wrong; the verifier adds `advisories: N affecting this bundle` with the ids, natures and `replacement_pack_version` of each, and exit code 0 stays 0 |
| Product side | the product re-evaluates affected architectures with the replacement pack, records `pack_advisory_applied` (advisory id, old and new pack version) on each evidence chain, and notifies customers as their contract states |

Until wave 2 lands, a reader applies the table by hand: compare the pack versions the report names with this file.
