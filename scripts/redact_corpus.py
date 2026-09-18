#!/usr/bin/env python3
"""Copy the regulatory corpus into this repository, withholding verbatim text we may not republish.

Every clause record carries a ``licence`` field naming the source of the text (see NOTICE.md).
Only sources whose terms permit redistribution keep their ``excerpt`` (the short verbatim quote);
for every other source the verbatim fields are emptied and the record is marked
``"redacted": "licence"``. Ids, references, titles, our own paraphrase (``summary``), our own
``note``, dates, tags and the source URL are always kept, so every citation stays resolvable and
the reader can go to the official text themselves.

Usage:
    python3 scripts/redact_corpus.py --src /path/to/product/corpus --dst corpus [--check]
    python3 scripts/redact_corpus.py --dst corpus --inventory-only

``--check`` reports what would change without writing (exit 1 if anything would change).
The script is idempotent: running it twice produces byte-identical output.

Stdlib only, no dependencies.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter

# Fields that may hold verbatim text from the source document. Emptied when the licence of the
# record does not permit redistribution. `summary` and `note` are our own words and stay.
VERBATIM_FIELDS = ("excerpt", "text", "verbatim", "quote", "body")

# licence value -> may we republish a verbatim excerpt here?
#
#   eu-law       EU legislation on EUR-Lex; reuse permitted with attribution
#                (Commission Decision 2011/833/EU).
#   admin.ch     Swiss federal law on Fedlex; official texts, freely reproducible with the source.
#   ch-law       ditto (Swiss federal act text).
#   finma        FINMA circulars and guidance; published supervisory documents.
#   nist-public  NIST publications; work of the US federal government, public domain.
#   owasp        OWASP project content; CC BY-SA 4.0 — attribution required (see NOTICE.md).
#   public       public-domain government text; see PUBLIC_REGIME_OK for the per-regime split.
#   iso          ISO/IEC standards; copyright-protected, text never reproduced.
#   iec          IEC standards; copyright-protected, text never reproduced.
#   ispe         ISPE GAMP guides; licensed to the purchaser, text never reproduced.
#   csa          Cloud Security Alliance; CC BY-NC-SA — non-commercial only, so not republished here.
#   cis-benchmark CIS Benchmarks; CC BY-NC-SA — non-commercial only, so not republished here.
#   microsoft-docs Microsoft Learn; terms vary by page, not confirmed for redistribution.
LICENCE_ALLOWS_TEXT = {
    "eu-law": True,
    "admin.ch": True,
    "ch-law": True,
    "finma": True,
    "nist-public": True,
    "owasp": True,
    "public": True,  # narrowed by PUBLIC_REGIME_OK below
    "iso": False,
    "iec": False,
    "ispe": False,
    "csa": False,
    "cis-benchmark": False,
    "microsoft-docs": False,
}

# `public` is used for two different things in the source corpus. Only regimes listed here are
# US federal government works (public domain); anything else marked `public` is treated as
# unconfirmed and redacted.
PUBLIC_REGIME_OK = {"FDA"}  # 21 CFR Part 11 via eCFR — US Government work

# Human-readable licence names for the inventory output and NOTICE.md.
LICENCE_NAMES = {
    "eu-law": "EU law (EUR-Lex) — reuse permitted with attribution, Decision 2011/833/EU",
    "admin.ch": "Swiss federal texts (Fedlex) — official publication",
    "ch-law": "Swiss federal act text (Fedlex) — official publication",
    "finma": "FINMA circulars and guidance — published supervisory documents",
    "nist-public": "NIST publications — US Government work, public domain",
    "owasp": "OWASP — CC BY-SA 4.0, attribution required",
    "public": "government publication (public domain where the regime is a US federal work)",
    "iso": "ISO/IEC — copyright-protected, not redistributable",
    "iec": "IEC — copyright-protected, not redistributable",
    "ispe": "ISPE GAMP — licensed to the purchaser, not redistributable",
    "csa": "Cloud Security Alliance — CC BY-NC-SA 4.0, non-commercial only",
    "cis-benchmark": "CIS Benchmarks — CC BY-NC-SA 4.0, non-commercial only",
    "microsoft-docs": "Microsoft Learn — terms not confirmed for redistribution",
}


def may_publish_text(record: dict) -> bool:
    """True when the verbatim excerpt of this record may be redistributed from here."""
    licence = str(record.get("licence", "")).strip().lower()
    if licence == "public":
        return str(record.get("regime", "")).strip().upper() in PUBLIC_REGIME_OK
    return LICENCE_ALLOWS_TEXT.get(licence, False)


def redact(record: dict) -> tuple[dict, bool]:
    """Return the publishable record and whether anything was withheld."""
    out = dict(record)
    if may_publish_text(record):
        out.pop("redacted", None)
        return out, False
    for field in VERBATIM_FIELDS:
        if field in out and out[field]:
            out[field] = ""
    # The marker is always set for a non-redistributable source, even when the record never held
    # an excerpt, so a reader can tell "references only" from "nothing to quote".
    out["redacted"] = "licence"
    return out, True


def process_file(src: pathlib.Path, dst: pathlib.Path, check: bool, stats: Counter) -> bool:
    records = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise SystemExit(f"{src}: expected a JSON array of clause records")
    out = []
    for record in records:
        publishable, withheld = redact(record)
        licence = str(record.get("licence", "<none>"))
        stats[("entries", licence)] += 1
        if any(record.get(field) for field in VERBATIM_FIELDS):
            stats[("text-in-source", licence)] += 1
        if withheld:
            stats[("redacted", licence)] += 1
            if any(record.get(field) for field in VERBATIM_FIELDS):
                stats[("text-removed", licence)] += 1
        out.append(publishable)
    rendered = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    if check:
        current = dst.read_text(encoding="utf-8") if dst.exists() else ""
        return current != rendered
    dst.parent.mkdir(parents=True, exist_ok=True)
    changed = not dst.exists() or dst.read_text(encoding="utf-8") != rendered
    if changed:
        dst.write_text(rendered, encoding="utf-8")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", type=pathlib.Path, help="product corpus directory (holds regimes/ and disclaimers.json)")
    ap.add_argument("--dst", type=pathlib.Path, default=pathlib.Path("corpus"), help="corpus directory in this repository")
    ap.add_argument("--check", action="store_true", help="report differences, write nothing, exit 1 if any")
    ap.add_argument("--inventory-only", action="store_true", help="print the licence inventory of --dst and exit")
    args = ap.parse_args()

    if args.inventory_only:
        stats: Counter = Counter()
        for path in sorted((args.dst / "regimes").glob("*.json")):
            for record in json.loads(path.read_text(encoding="utf-8")):
                stats[("entries", str(record.get("licence", "<none>")))] += 1
                if record.get("redacted"):
                    stats[("redacted", str(record.get("licence", "<none>")))] += 1
                if record.get("excerpt"):
                    stats[("text-kept", str(record.get("licence", "<none>")))] += 1
        print_inventory(stats)
        return 0

    if args.src is None:
        ap.error("--src is required unless --inventory-only is given")
    src_regimes = args.src / "regimes"
    if not src_regimes.is_dir():
        raise SystemExit(f"{src_regimes}: not a directory")

    stats = Counter()
    changed_files = []
    for path in sorted(src_regimes.glob("*.json")):
        if process_file(path, args.dst / "regimes" / path.name, args.check, stats):
            changed_files.append(f"regimes/{path.name}")

    # disclaimers.json is our own wording (one sentence per regime) and is copied verbatim.
    disclaimers = args.src / "disclaimers.json"
    if disclaimers.is_file():
        rendered = json.dumps(json.loads(disclaimers.read_text(encoding="utf-8")), indent=2, ensure_ascii=False) + "\n"
        target = args.dst / "disclaimers.json"
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != rendered:
                changed_files.append("disclaimers.json")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists() or target.read_text(encoding="utf-8") != rendered:
                target.write_text(rendered, encoding="utf-8")
                changed_files.append("disclaimers.json")

    print_inventory(stats)
    if changed_files:
        print(f"\n{'would change' if args.check else 'written'}: {len(changed_files)} file(s)")
        for name in changed_files:
            print(f"  {name}")
    else:
        print("\ncorpus already up to date")
    return 1 if (args.check and changed_files) else 0


def print_inventory(stats: Counter) -> None:
    licences = sorted({licence for kind, licence in stats if kind == "entries"})
    width = max((len(x) for x in licences), default=8)
    print(f"{'licence'.ljust(width)}  entries  redacted  text             excerpts                    source")
    for licence in licences:
        entries = stats[("entries", licence)]
        redacted = stats[("redacted", licence)]
        removed = stats[("text-removed", licence)]
        with_text = stats[("text-in-source", licence)] + stats[("text-kept", licence)]
        kept = "kept" if redacted == 0 else ("references only" if redacted == entries else "mixed")
        note = f"{with_text} with excerpt"
        if removed:
            note += f", {removed} stripped"
        print(f"{licence.ljust(width)}  {entries:7d}  {redacted:8d}  {kept:15s}  {note:26s}  {LICENCE_NAMES.get(licence, 'unknown — treated as not redistributable')}")


if __name__ == "__main__":
    sys.exit(main())
