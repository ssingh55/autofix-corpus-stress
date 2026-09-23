"""Score stress plants after an autofix run.

S1/S2 plants share scan ids (17 and 127 are planted in both), so they are scored by whether
their exact source line survives in the autofix PR head. S3/S3b plants (`by: id`) are scored
from the rescan instead: ids 39 and 42 are unique to those plants in each APK, and a correct
fix need not touch the planted line (e.g. making the guarding permission signature-level).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

import yaml


def risky(analyses: dict) -> dict[int, int]:
    """Map vulnerability id to computed risk, for analyses above Passed.

    Vendored from autofix-corpus-android tools/score.py so this repo never fetches code.
    """
    return {a["vulnerability"]: a.get("computed_risk", 0)
            for a in analyses.get("results", [])
            if a.get("computed_risk", 0) > 0}


def apk_of(plant: dict) -> str:
    """The APK (gradle module) a plant is built into: s3b/... is s3b, everything else app."""
    return "s3b" if plant["file"].startswith("s3b/") else "app"


def _expectation(plant: dict, fixed: bool) -> str:
    if plant["expect"] == "fixed":
        return "fixed-as-expected" if fixed else "missed"
    return "fixed-unexpectedly" if fixed else "missed-as-expected"


def _text_result(plant: dict, base_n: int, head_n: int) -> str:
    if plant["expect"] == "record":
        return f"removed-{base_n - head_n}-of-{base_n}"
    return _expectation(plant, head_n == 0)


def _id_result(plant: dict, scans: dict) -> str:
    before, after = scans.get(apk_of(plant), (None, None))
    if before is None or plant["id"] not in before:
        return "detection-gap"
    if after is None:
        return "no-after-scan"
    return _expectation(plant, plant["id"] not in after)


def score_plants(plants: list[dict], read_base: Callable[[str], str],
                 read_head: Callable[[str], str], scans: dict | None = None) -> list[dict]:
    """One row per plant. `count` is how often the line occurs at corpus-base.

    scans: apk -> (before risky ids, after risky ids), used by `by: id` plants.
    """
    rows = []
    for p in plants:
        base_n = read_base(p["file"]).count(p["line"])
        head_n = read_head(p["file"]).count(p["line"])
        if base_n != p["count"]:
            result = "corpus-error"
        elif p.get("by") == "id":
            result = _id_result(p, scans or {})
        else:
            result = _text_result(p, base_n, head_n)
        rows.append({"case": p["case"], "id": p["id"], "by": p.get("by", "text"),
                     "remaining": head_n, "result": result})
    return rows


def sanity_gaps(plants: list[dict], before_by_apk: dict[str, dict[int, int]]) -> list[str]:
    """Every planted id must be reported by the baseline scan of its APK."""
    missing = {f"{apk_of(p)}:{p['id']}" for p in plants
               if p["id"] not in before_by_apk.get(apk_of(p), {})}
    return sorted(missing)


def unrelated_manifest_changes(diff_text: str, allowed: list[str]) -> int:
    """Changed manifest lines that mention none of the allowed markers."""
    changed = [line for line in diff_text.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    return sum(1 for line in changed if not any(a in line for a in allowed))


def _git_show(ref: str) -> Callable[[str], str]:
    def read(path: str) -> str:
        proc = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
        if proc.returncode != 0:
            # A bad ref or a renamed/deleted file must never read as "line gone = fixed".
            raise RuntimeError(f"git show {ref}:{path} failed: {proc.stderr.strip()}")
        return proc.stdout
    return read


def _apk_files(pairs: list[str]) -> dict[str, dict[int, int]]:
    out = {}
    for pair in pairs:
        apk, _, path = pair.partition("=")
        if not path:
            raise ValueError(f"expected APK=PATH, got {pair!r}")
        out[apk] = risky(json.loads(Path(path).read_text()))
    return out


def _render(rows: list[dict], unrelated: dict, partial: str, meta: list[str]) -> str:
    title = "### Stress scorecard" + (f" PARTIAL: {partial}" if partial else "")
    md = [title, ""]
    md += [f"- {m.replace('=', ': ', 1)}" for m in meta]
    md += [""] if meta else []
    md += ["| case | id | scored by | remaining | result |", "|---|---|---|---|---|"]
    md += [f"| {r['case']} | {r['id']} | {r['by']} | {r['remaining']} | {r['result']} |"
           for r in rows]
    md += ["", "Unrelated manifest lines changed: "
           + ", ".join(f"`{p}` {n}" for p, n in unrelated.items())]
    return "\n".join(md) + "\n"


def _score(args, spec: dict) -> int:
    before, after = _apk_files(args.before), _apk_files(args.after)
    scans = {apk: (before.get(apk), after.get(apk)) for apk in set(before) | set(after)}
    rows = score_plants(spec["plants"], _git_show(args.base), _git_show(args.head), scans)
    unrelated = {}
    for path, allowed in spec.get("manifest_allowed_changes", {}).items():
        diff = subprocess.run(["git", "diff", args.base, args.head, "--", path],
                              capture_output=True, text=True, check=True).stdout
        unrelated[path] = unrelated_manifest_changes(diff, allowed)
    regressions = {apk: sorted(set(after[apk]) - set(before[apk]))
                   for apk in sorted(set(before) & set(after))}
    md = _render(rows, unrelated, args.partial, args.meta)
    md += "".join(f"\n{apk}: regressions (new ids): {ids or 'none'}\n"
                  for apk, ids in regressions.items())
    Path(args.summary).write_text(md)
    Path(args.json).write_text(json.dumps(
        {"plants": rows, "unrelated_manifest": unrelated, "regressions": regressions,
         "partial": args.partial, "meta": args.meta}, indent=2))
    return 0


def main(argv: list[str]) -> int:
    """CLI: `gate` (every planted id in its baseline scan) or `score` (write reports)."""
    parser = argparse.ArgumentParser(prog="score_plants.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    gate = sub.add_parser("gate")
    gate.add_argument("--expected", required=True)
    gate.add_argument("--before", action="append", default=[], help="APK=analyses.json")
    sc = sub.add_parser("score")
    sc.add_argument("--expected", required=True)
    sc.add_argument("--base", required=True)
    sc.add_argument("--head", required=True)
    sc.add_argument("--summary", required=True)
    sc.add_argument("--json", required=True)
    sc.add_argument("--before", action="append", default=[], help="APK=analyses.json")
    sc.add_argument("--after", action="append", default=[], help="APK=analyses.json")
    sc.add_argument("--partial", default="", help="stamp the scorecard PARTIAL with this reason")
    sc.add_argument("--meta", action="append", default=[], help="KEY=VALUE header line")
    args = parser.parse_args(argv)

    spec = yaml.safe_load(Path(args.expected).read_text())
    if args.cmd == "gate":
        missing = sanity_gaps(spec["plants"], _apk_files(args.before))
        sys.stdout.write(f"stress plants not detected: {missing or 'none'}\n")
        return 1 if missing else 0
    return _score(args, spec)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
