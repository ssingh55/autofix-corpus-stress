import score_plants as sp

PLANTS = [
    {"case": "S1-stress", "id": 17, "file": "a.kt", "line": "LOG_S1", "count": 1, "expect": "missed"},
    {"case": "S1-control", "id": 127, "file": "a.kt", "line": "RAND", "count": 1, "expect": "fixed"},
    {"case": "S2-dup", "id": 17, "file": "b.kt", "line": "DUP", "count": 3, "expect": "record"},
]


def reader(files):
    return lambda path: files.get(path, "")


def by_case(rows, case):
    return next(r for r in rows if r["case"] == case)


def test_fixed_and_expected_miss():
    base = reader({"a.kt": "LOG_S1\nRAND\n", "b.kt": "DUP\nDUP\nDUP\n"})
    head = reader({"a.kt": "LOG_S1\n", "b.kt": "DUP\nDUP\nDUP\n"})
    rows = sp.score_plants(PLANTS, base, head)
    assert by_case(rows, "S1-control")["result"] == "fixed-as-expected"
    assert by_case(rows, "S1-stress")["result"] == "missed-as-expected"


def test_unexpected_fix_past_cap_is_flagged():
    base = reader({"a.kt": "LOG_S1\nRAND\n"})
    head = reader({"a.kt": ""})
    assert by_case(sp.score_plants(PLANTS, base, head), "S1-stress")["result"] == "fixed-unexpectedly"


def test_duplicates_report_remaining_count():
    base = reader({"b.kt": "DUP\nDUP\nDUP\n"})
    head = reader({"b.kt": "DUP\n"})
    row = by_case(sp.score_plants(PLANTS, base, head), "S2-dup")
    assert row["remaining"] == 1 and row["result"] == "removed-2-of-3"


def test_base_mismatch_is_corpus_error():
    base = reader({"a.kt": ""})
    head = reader({"a.kt": ""})
    assert by_case(sp.score_plants(PLANTS, base, head), "S1-control")["result"] == "corpus-error"


def test_unrelated_manifest_changes():
    diff = "\n".join([
        "--- a/AndroidManifest.xml", "+++ b/AndroidManifest.xml", "@@ -1,3 +1,3 @@",
        '-        <receiver android:name=".Stub482Receiver" android:exported="true" />',
        '+        <receiver android:name=".Stub482Receiver" android:exported="false" />',
        '-        <activity android:name=".Stub7Activity" android:exported="false" />',
        '+        <activity android:name=".Stub7Activity" android:exported="false" android:x="1" />',
    ])
    assert sp.unrelated_manifest_changes(diff, ["Stub482Receiver", "<permission"]) == 2


# --- final-review fixes: id-level S3/S3b scoring (I6), full-line 88, vendored risky (M4),
# --- full sanity gate (M5), git read failures raise (M6), expected.yaml tied to generate (M9).
import json
import subprocess
from pathlib import Path

import pytest
import yaml

import generate as g

ROOT = Path(__file__).resolve().parent.parent
S3_PLANTS = [
    {"case": "S3", "id": 42, "file": "app/m.xml", "line": "VULN42", "count": 1, "expect": "fixed",
     "by": "id"},
    {"case": "S3b", "id": 39, "file": "s3b/m.xml", "line": "VULN39", "count": 1,
     "expect": "missed", "by": "id"},
]
S3_FILES = {"app/m.xml": "VULN42\n", "s3b/m.xml": "VULN39\n"}


def spec():
    return yaml.safe_load((ROOT / "expected.yaml").read_text())


def analyses(ids):
    return {"count": 60, "results": [{"vulnerability": i, "computed_risk": 2} for i in ids]
            + [{"vulnerability": 999, "computed_risk": 0}]}


def test_risky_keeps_only_positive_risk():
    assert sp.risky(analyses([17, 39])) == {17: 2, 39: 2}


def test_id_scored_plant_fixed_without_touching_the_line():
    # A signature-level <permission> clears 42 but leaves the activity line as it was.
    scans = {"app": ({42: 2}, {}), "s3b": ({39: 2}, {39: 2})}
    rows = sp.score_plants(S3_PLANTS, reader(S3_FILES), reader(S3_FILES), scans)
    assert by_case(rows, "S3")["result"] == "fixed-as-expected"
    assert by_case(rows, "S3")["remaining"] == 1
    assert by_case(rows, "S3b")["result"] == "missed-as-expected"


def test_id_scored_plant_still_reported_is_missed_even_if_line_changed():
    scans = {"app": ({42: 2}, {42: 2})}
    rows = sp.score_plants(S3_PLANTS, reader(S3_FILES), reader({"app/m.xml": ""}), scans)
    assert by_case(rows, "S3")["result"] == "missed"


def test_id_scored_plant_without_scans():
    rows = sp.score_plants(S3_PLANTS, reader(S3_FILES), reader(S3_FILES),
                           {"app": ({42: 2}, None)})
    assert by_case(rows, "S3")["result"] == "no-after-scan"
    assert by_case(rows, "S3b")["result"] == "detection-gap"


def test_apk_of():
    assert sp.apk_of({"file": "s3b/src/main/AndroidManifest.xml"}) == "s3b"
    assert sp.apk_of({"file": "app/src/main/AndroidManifest.xml"}) == "app"


def test_s3_rows_are_id_scored_and_s1_s2_are_text_scored():
    for p in spec()["plants"]:
        assert (p.get("by") == "id") == p["case"].startswith("S3"), p["case"]


def test_88_fix_that_keeps_the_receiver_name_still_clears():
    p88 = next(p for p in spec()["plants"] if p["id"] == 88)
    base = g.generate(Path("/nonexistent"))[p88["file"]].decode()
    fixed = base.replace('IntentFilter("com.appknox.stress.PING"))',
                         'IntentFilter("com.appknox.stress.PING"), RECEIVER_NOT_EXPORTED)')
    assert "registerReceiver(spreadReceiver" in fixed
    row = sp.score_plants([p88], reader({p88["file"]: base}), reader({p88["file"]: fixed}))[0]
    assert row["result"] == "fixed-as-expected"


def test_every_plant_line_occurs_count_times_in_generated_files():
    files = g.generate(Path("/nonexistent"))
    for p in spec()["plants"]:
        assert files[p["file"]].decode().count(p["line"]) == p["count"], (p["case"], p["id"])


def test_sanity_gate_checks_every_planted_id_in_its_apk():
    plants = spec()["plants"]
    app_ids = {p["id"] for p in plants if sp.apk_of(p) == "app"}
    full = {"app": {i: 2 for i in app_ids}, "s3b": {39: 2}}
    assert sp.sanity_gaps(plants, full) == []
    for vid in (16, 88, 93):  # the ids the old hardcoded gate skipped
        partial = {"app": {i: 2 for i in app_ids - {vid}}, "s3b": {39: 2}}
        assert sp.sanity_gaps(plants, partial) == [f"app:{vid}"]
    assert sp.sanity_gaps(plants, {"app": full["app"], "s3b": {}}) == ["s3b:39"]


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    for rel, text in {"a.kt": "LOG_S1\nRAND\n", "b.kt": "DUP\nDUP\nDUP\n", **S3_FILES}.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text)
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "base")
    base = git(r, "rev-parse", "HEAD")
    (r / "a.kt").write_text("LOG_S1\n")
    (r / "b.kt").write_text("DUP\n")
    git(r, "commit", "-q", "-am", "fix")
    return r, base, git(r, "rev-parse", "HEAD")


def test_git_show_raises_on_bad_ref_or_missing_path(repo, monkeypatch):
    r, base, head = repo
    monkeypatch.chdir(r)
    assert sp._git_show(base)("a.kt") == "LOG_S1\nRAND\n"
    with pytest.raises(RuntimeError, match="no-such-ref"):
        sp._git_show("no-such-ref")("a.kt")
    with pytest.raises(RuntimeError, match="renamed.kt"):
        sp._git_show(head)("renamed.kt")


def test_main_score_against_a_git_repo(repo, monkeypatch, tmp_path):
    r, base, head = repo
    monkeypatch.chdir(r)
    exp = tmp_path / "e.yaml"
    exp.write_text(yaml.safe_dump({"plants": PLANTS + S3_PLANTS,
                                   "manifest_allowed_changes": {"app/m.xml": ["VULN42"]}}))
    files = {}
    for name, ids in {"ba": [42], "aa": [7], "bs": [39], "as": [39]}.items():
        files[name] = tmp_path / f"{name}.json"
        files[name].write_text(json.dumps(analyses(ids)))
    out_md, out_json = tmp_path / "s.md", tmp_path / "s.json"
    rc = sp.main(["score", "--expected", str(exp), "--base", base, "--head", head,
                  "--summary", str(out_md), "--json", str(out_json),
                  "--before", f"app={files['ba']}", "--after", f"app={files['aa']}",
                  "--before", f"s3b={files['bs']}", "--after", f"s3b={files['as']}",
                  "--partial", "app run truncated", "--meta", "appknox-go=abc123"])
    assert rc == 0
    report = json.loads(out_json.read_text())
    results = {(p["case"], p["id"]): p["result"] for p in report["plants"]}
    assert results == {("S1-stress", 17): "missed-as-expected",
                       ("S1-control", 127): "fixed-as-expected",
                       ("S2-dup", 17): "removed-2-of-3",
                       ("S3", 42): "fixed-as-expected",
                       ("S3b", 39): "missed-as-expected"}
    assert report["regressions"] == {"app": [7], "s3b": []}
    md = out_md.read_text()
    assert md.startswith("### Stress scorecard PARTIAL: app run truncated")
    assert "- appknox-go: abc123" in md and "app: regressions (new ids): [7]" in md


def test_main_gate_exit_codes(tmp_path):
    exp = tmp_path / "e.yaml"
    exp.write_text(yaml.safe_dump({"plants": S3_PLANTS}))
    app, s3b = tmp_path / "a.json", tmp_path / "s.json"
    app.write_text(json.dumps(analyses([42])))
    s3b.write_text(json.dumps(analyses([])))
    argv = ["gate", "--expected", str(exp), "--before", f"app={app}", "--before", f"s3b={s3b}"]
    assert sp.main(argv) == 1
    s3b.write_text(json.dumps(analyses([39])))
    assert sp.main(argv) == 0
