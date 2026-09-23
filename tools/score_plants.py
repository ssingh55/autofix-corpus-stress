"""Score stress plants by whether their exact source line survives in the autofix PR head."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

import yaml


def _result(plant: dict, base_n: int, head_n: int) -> str:
    if base_n != plant["count"]:
        return "corpus-error"
    if plant["expect"] == "record":
        return f"removed-{base_n - head_n}-of-{base_n}"
    fixed = head_n == 0
    if plant["expect"] == "fixed":
        return "fixed-as-expected" if fixed else "missed"
    return "fixed-unexpectedly" if fixed else "missed-as-expected"


def score_plants(plants: list[dict], read_base: Callable[[str], str],
                 read_head: Callable[[str], str]) -> list[dict]:
    """One row per plant. `count` is how often the line occurs at corpus-base."""
    rows = []
    for p in plants:
        base_n = read_base(p["file"]).count(p["line"])
        head_n = read_head(p["file"]).count(p["line"])
        rows.append({"case": p["case"], "id": p["id"], "remaining": head_n,
                     "result": _result(p, base_n, head_n)})
    return rows


def unrelated_manifest_changes(diff_text: str, allowed: list[str]) -> int:
    """Changed manifest lines that mention none of the allowed markers."""
    changed = [line for line in diff_text.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    return sum(1 for line in changed if not any(a in line for a in allowed))


def _git_show(ref: str) -> Callable[[str], str]:
    def read(path: str) -> str:
        proc = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
        return proc.stdout if proc.returncode == 0 else ""
    return read


def main(argv: list[str]) -> int:
    """CLI entry point: score plants at --base/--head refs, writing --summary and --json."""
    parser = argparse.ArgumentParser(prog="score_plants.py")
    parser.add_argument("--expected", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--json", required=True)
    args = parser.parse_args(argv)

    spec = yaml.safe_load(Path(args.expected).read_text())
    rows = score_plants(spec["plants"], _git_show(args.base), _git_show(args.head))
    unrelated = {}
    for path, allowed in spec.get("manifest_allowed_changes", {}).items():
        diff = subprocess.run(["git", "diff", args.base, args.head, "--", path],
                              capture_output=True, text=True, check=True).stdout
        unrelated[path] = unrelated_manifest_changes(diff, allowed)

    md = ["### Stress scorecard", "", "| case | id | remaining | result |", "|---|---|---|---|"]
    md += [f"| {r['case']} | {r['id']} | {r['remaining']} | {r['result']} |" for r in rows]
    md += ["", "Unrelated manifest lines changed: "
           + ", ".join(f"`{p}` {n}" for p, n in unrelated.items())]
    Path(args.summary).write_text("\n".join(md) + "\n")
    Path(args.json).write_text(json.dumps({"plants": rows, "unrelated_manifest": unrelated}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
