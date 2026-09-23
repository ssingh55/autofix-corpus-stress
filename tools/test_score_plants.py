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
