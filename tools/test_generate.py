from pathlib import Path

import generate as g

CAP = 256 * 1024


def files():
    return g.generate(Path("/nonexistent"))


def offset(content: bytes, line: str) -> int:
    return content.index(line.encode())


def test_deterministic():
    assert files() == files()


def test_s1_size_and_control_inside_cap():
    s1 = files()[g.S1_PATH]
    assert 340_000 <= len(s1) <= 400_000
    assert offset(s1, g.S1_CONTROL_LINE) < CAP


def test_s1_stress_past_cap():
    s1 = files()[g.S1_PATH]
    assert offset(s1, g.S1_STRESS_LINE) > CAP + 40_000


def test_s2_under_cap_with_three_exact_duplicates():
    s2 = files()[g.S2_PATH]
    assert len(s2) < CAP
    assert s2.count(g.S2_DUP_LINE.encode()) == 3
    assert s2.count(b"\n") >= 6000


def test_s2_spread_positions():
    s2 = files()[g.S2_PATH]
    for _vid, line in g.S2_SPREAD:
        assert s2.count(line.encode()) == 1, line
    fractions = sorted(offset(s2, line) / len(s2) for _vid, line in g.S2_SPREAD)
    assert fractions[0] < 0.10 and fractions[-1] > 0.90


def test_s3_manifest_components_one_per_line_and_two_vulnerable():
    m = files()[g.S3_MANIFEST].decode()
    comp_lines = [l for l in m.splitlines()
                  if l.strip().startswith(("<activity", "<service", "<receiver"))
                  and ".MainActivity" not in l]
    assert len(comp_lines) == 500
    assert all(l.rstrip().endswith("/>") for l in comp_lines)
    exported = [l for l in comp_lines if 'exported="true"' in l]
    assert exported == [g.S3_VULN_ACTIVITY, g.S3_VULN_RECEIVER]


def test_s3_vulnerable_names_have_matching_stub_classes():
    stubs = files()[g.S3_STUBS].decode()
    assert "class Stub482Receiver : android.content.BroadcastReceiver()" in stubs
    assert "class Stub252Activity : android.app.Activity()" in stubs
    s3b_stubs = files()[g.S3B_STUBS].decode()
    assert "class Stub3590Receiver : android.content.BroadcastReceiver()" in s3b_stubs


def test_s3b_vulnerable_receiver_past_cap():
    m = files()[g.S3B_MANIFEST]
    assert len(m) > CAP
    assert offset(m, g.S3B_VULN_RECEIVER) > CAP


def test_check_detects_drift(tmp_path):
    g.write(tmp_path)
    assert g.check(tmp_path) == []
    target = tmp_path / g.S1_PATH
    target.write_bytes(target.read_bytes() + b"// drift\n")
    assert g.check(tmp_path) == [g.S1_PATH]
