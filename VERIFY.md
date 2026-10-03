# Verifying a Sixi Assure bundle offline

`assure-check verify` checks what a Sixi Assure export says about itself, on your machine, with no account and no
network. It is the same code as the product's `assure verify` (`verify/` here is synced from the product's
`server/internal/verify` by its `scripts/sync-public-rules.sh`; `VERIFY.sha256` lists the sha256 of every synced
file), under this repository's licence (Apache-2.0).

## Build it

```bash
go build -trimpath -o assure-check ./cmd/assure-check     # from a checkout of this repository
assure-check verify --help
```

The product builds the same verifier reproducibly with `make build-verify` (static, `-trimpath`, no VCS stamp, empty
build id, pinned Go toolchain; two builds must hash the same) and prints the binary's sha256. Compare it with the value
published on the trust centre and with `verifier_version` in a bundle's `manifest.json`.

## Verify a bundle

```bash
# evidence-keys.json  the organisation's GET /evidence/keys, saved from the product
# tsa-root.pem        the time-stamp authority's root (default: the system roots on Linux and BSD)
# advisories.json     this repository's rule-pack advisory list
# bundle.zip          or the unpacked directory, a report.json, a spot-check file or a chain export
assure-check verify --keys evidence-keys.json --roots tsa-root.pem --advisories advisories.json bundle.zip
```

Flags may come before or after the path. `--json` prints the result as one JSON document; `--strict` exits 1 when a
check could not be made; `--rules <dir>` gives the packs to re-run when the input carries none (default `packs`);
`--allow-pack-mismatch` re-runs them even when their hash is not the report's and prints the per-pack difference;
`--at <RFC 3339>` sets the verification time for the long-term rule; `--receipts <file>` (repeatable or
comma-separated) names reanchor receipts kept elsewhere (below). Exit codes: `0` no check failed, `1` a check failed,
`2` usage or an input that cannot be read at all.

Every line is `pass`, `FAIL`, `NOT CHECKED`, `FLAG` or `info`. A check whose input is absent says
**"not present in this input"** and is never counted as passed.

## The bundle

| Member | What the verifier does with it |
|---|---|
| `manifest.json` | `{bundle_id, produced_at, producer_build, verifier_version, items: [{path, sha256}]}`: every listed member must hash as listed; a member that is not listed, or does not match, is reported and not read |
| `report.json`, `report.json.sig` | the JSON Assurance Report and its detached signature (`signature_format: sixi-assure/export-signature/v1`): the file's sha256, the Ed25519 signature over the versioned message, the key it names in the key list, the signing time inside the key's validity window, and the snapshot, pack, corpus and chain hashes the signature states equal to the report's |
| `snapshot.json` | the canonical model snapshot; its sha256 is the report's `snapshot_hash` and equals the copy the report embeds |
| `chain.json` | the chain export (`GET /audit/{arch_id}`): every hash recomputed from genesis, the head, each event's `anchored_by`, and the report's chain head found in the chain |
| `anchors/<id>.tsr`, `anchors/<id>.certs.pem` | each RFC 3161 token (DER) and its certificates (PEM): the token's sha256 is the receipt the chain records, it signs the anchored head hash, its signature and time-stamping usage verify, and its signer chains to `--roots` at the signed time |
| `keys.json` | the organisation's keys (`key_id`, `public_key`, `custody`, `provider`, `state`, `valid_from`, `valid_to`); `--keys` takes precedence and the bundle's list must agree with it |
| `rules/` | the rule packs (`*.yaml`) and `policy.yaml`: their combined hash must be the report's `pack_hash`, else the run is refused |
| `corpus/records.json` | the corpus records at the report's `corpus_hash` |
| `<bundle>.zip.sig` | beside the zip, not in it: the zip's own detached signature |
| `<input>.reanchor-<time>.json` | beside the bundle or chain export, not in it: a receipt of `assure reanchor` (schema `sixi.assure.reanchor.v1`, the token and certificates inline). Each one is read and checked like an anchor of the export, under the check name `reanchor receipt <file>`; a receipt for another chain, or a file of that name that is not a receipt, fails |

## What it checks

1. **Chain.** Every event's hash recomputed from genesis: `sha256(prev_hash|payload_hash|type|actor|version|ts)` over
   the canonical payload, `ts` in RFC 3339 UTC truncated to microseconds. Published test vectors:
   `verify/testdata/chain-vectors.json`; each is checkable with `jq` and `sha256sum` (the file says how).
2. **Signatures.** Against the key the signature names, from `--keys` or the bundle's `keys.json` — never a key the
   signed file carries. A signature dated outside its key's window fails. Each key's custody is printed: a key with
   custody `vendor` is held by Sixi, so a signature by it relies on the vendor's custodian.
3. **Anchors.** Each token against the head it signs and its certificate chain; the events after the last anchor are
   printed as "events after <time> are unanchored". **Long-term rule:** an authority chain that has expired by the
   verification time is accepted when a later anchor, valid then, signs the same or a later head (its hash commits to
   every event before it); otherwise the anchor fails and the chain must be re-anchored (`assure reanchor`). The
   receipts `assure reanchor` writes beside the input, and those named with `--receipts`, count as such later anchors:
   they need no chain_anchored record, because reanchoring changes nothing in the exported chain.
4. **Reproducibility.** The packs are reloaded (the bundle's `rules/`, else `--rules`), their combined hash must be the
   report's, and the rules re-run on the snapshot: the (rule, element) results are listed as matched, missing from the
   report, or in the report but not produced. The organisation's allowed regions and regime filter and the knowledge
   facts are not in a bundle: the policy table's defaults and the model's own regimes are used, and drift rules stay
   silent; the output says so.
5. **Advisories.** With `--advisories`, an advisory against a pinned pack version is flagged with the affected rules
   that produced findings and those that stayed silent. It does not change the exit code: an advisory does not make a
   hash wrong (ADVISORIES.md).

The verifier opens no network connection: every input is a file. (The product's test suite runs it under a filter that
kills the process on its first socket.)

## What verification does not establish

Printed on every run:

- that the model matches the operated system;
- that the rules are complete or correct;
- that a corpus paraphrase is the law;
- that a key held by Sixi (custody vendor) was not misused by its custodian;
- that a signature here is a qualified electronic signature or seal under ZertES or eIDAS: it is a cryptographic
  integrity control.

## The reviewer bundle's members (docs/18 A5)

The product writes these members (`GET /exports/{id}/bundle`); `manifest.json` lists every one of them with its
sha256, and members the deployment could not produce under `omitted` with the reason.

| Member | Content |
|---|---|
| `manifest.json` | `bundle_id`, `kind` (`bundle` or `exit_bundle`), `produced_at`, `producer_build`, `verifier_version`, `workpaper_prefix` (`<bundle_id>/`), `items`, `omitted` |
| `report.json`, `report.json.sig` | the signed JSON Assurance Report and its detached signature |
| `report.pdf` | the printed report, when it was rendered |
| `snapshot.json` | the canonical snapshot the report embeds |
| `chain.json`, `anchors/<id>.tsr`, `anchors/<id>.certs.pem` | the chain export and every RFC 3161 receipt |
| `keys.json`, `key_signing_log.json` | the organisation's keys, its key chain and where each key's use is logged |
| `policy.json` | the organisation's policy at bundle time: `allowed_regions` and `regime_filter`. When it is present the re-run uses it (the organisation's allowed regions, and the model's regimes filtered by the organisation's enabled regimes) and says so; without it the defaults above apply. The report's findings were computed when the version was saved, under the policy of that moment; the member's `stored_findings.match` says whether they agree with this policy, so a findings mismatch with `match: false` is a changed policy, not a changed rule |
| `rules/*.yaml`, `rules/policy.yaml`, `corpus/records.json` | the packs and the corpus at the report's hashes |
| `roles.json`, `patches.json`, `reviews.json`, `population.json`, `applicability.json`, `custody.json` | people and roles (ids only), accepted patches (hashes only), design reviews, the obligation population at the chain head, declared applicability, custody of evidence artefacts — read by a person, not checked by the verifier |
| `LIMITATIONS.md`, `README.md` | what the bundle is and is not, and how to verify it |

The organisation's **exit bundle** holds each architecture's bundle as `architectures/<arch id>.zip` with its
`.zip.sig` beside it inside the zip: unzip it and verify each one as above. The exit zip itself verifies as a bundle
without a report (its manifest, keys and signature).

## Re-measuring the rule packs (docs/18 B4)

A bundle states, in LIMITATIONS.md, each pack's precision and recall on the golden set with the pack's hash. Measure
the same packs yourself, offline, from a checkout of this repository:

    go run ./cmd/assure-eval -packs packs -policy policy.yaml -models golden-set/models -expected golden-set/expected

It checks every rule's positive and negative fixture, evaluates every golden model against `golden-set/expected/`,
and prints per pack its version, TP, FP, FN, precision, recall and content hash, the combined hash of the packs, and
the expectations counted per author (`golden-set/AUTHORS.md` in the product says who authored them; today every
expectation is the rule authors' own). Exit 0 when every fixture behaves and every pack holds precision ≥ 0.90 and
recall ≥ 0.85. The product's CLI runs the same measurement as `assure eval`. Compare the pack hashes with the ones the
bundle names: a different hash is a different measurement. What it does not establish: that the expectations are
right, or that the packs find what the golden set does not contain.
