"""Deterministic generator for the autofix stress corpus.

Every generated file is committed. `--check` fails when the committed bytes differ
from a fresh generation, so the planted offsets in test_generate.py always
describe what is actually in the repository.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

SEED = 20260923
PKG = "com.appknox.stress"
SRC = "app/src/main/java/com/appknox/stress"

S1_PATH = f"{SRC}/HugeFile.kt"
S2_PATH = f"{SRC}/GodActivity.kt"
S3_MANIFEST = "app/src/main/AndroidManifest.xml"
S3_STUBS = f"{SRC}/Stubs.kt"
S3B_MANIFEST = "s3b/src/main/AndroidManifest.xml"
S3B_STUBS = "s3b/src/main/java/com/appknox/stress/s3b/Stubs.kt"

S1_CONTROL_LINE = "    val s1Control = java.util.Random().nextInt(1_000_000)"
S1_STRESS_LINE = '    android.util.Log.d("S1", "past the read cap: session token refreshed")'
S2_DUP_LINE = '        android.util.Log.d("S2", "user event")'
S2_SPREAD = [
    (17, '        android.util.Log.d("S2Spread", "spread log start")'),
    (93, "        android.database.sqlite.SQLiteDatabase.create(null).rawQuery(\"SELECT * FROM t WHERE n = '\" + name + \"'\", null)"),
    (127, "        val spreadRandom = java.util.Random().nextInt()"),
    (16, '        val spreadCipher = javax.crypto.Cipher.getInstance("AES")'),
    (88, '        registerReceiver(spreadReceiver, android.content.IntentFilter("com.appknox.stress.PING"))'),
]
S3_VULN_ACTIVITY = ('        <activity android:name=".Stub252Activity" android:exported="true" '
                    'android:permission="com.appknox.stress.permission.NORMAL" />')
S3_VULN_RECEIVER = '        <receiver android:name=".Stub482Receiver" android:exported="true" />'
S3B_VULN_RECEIVER = '        <receiver android:name=".Stub3590Receiver" android:exported="true" />'

KINDS = ("activity", "service", "receiver")
STUB_BASE = {
    "activity": "android.app.Activity()",
    "service": ("android.app.Service() { override fun onBind(i: android.content.Intent?)"
                ": android.os.IBinder? = null }"),
    "receiver": ("android.content.BroadcastReceiver() { override fun onReceive("
                 "c: android.content.Context?, i: android.content.Intent?) {} }"),
}


def _filler_fn(rng: random.Random, i: int) -> str:
    a, b = rng.randint(1, 999), rng.randint(1, 999)
    return (f"fun filler{i}(x: Int): Int {{\n"
            f"    val y = x * {a} + {b}\n"
            f"    return if (y % 2 == 0) y / 2 else y - {a}\n"
            f"}}\n\n")


def _s1(rng: random.Random) -> str:
    """~360 KB of top-level functions; control near 120 KB, stress near 330 KB."""
    out = [f"package {PKG}\n\n"]
    size, i = 0, 0
    placed_control = placed_stress = False
    while size < 360_000:
        if not placed_control and size >= 120_000:
            out.append(f"fun s1ControlPlant() {{\n{S1_CONTROL_LINE}\n}}\n\n")
            placed_control = True
        elif not placed_stress and size >= 330_000:
            out.append(f"fun s1StressPlant() {{\n{S1_STRESS_LINE}\n}}\n\n")
            placed_stress = True
        chunk = _filler_fn(rng, i)
        out.append(chunk)
        size += len(chunk)
        i += 1
    return "".join(out)


def _s2(rng: random.Random) -> str:
    """~6k-line single Activity: spread plants at ~2%, 50%, 98%, and three identical dup lines."""
    methods = 2000
    spread_at = {40: S2_SPREAD[0:2], 1000: S2_SPREAD[2:4], 1960: S2_SPREAD[4:5]}
    dup_at = {200, 800, 1400}
    body = [f"package {PKG}\n\n", "import android.app.Activity\n",
            "import android.content.BroadcastReceiver\n", "import android.content.Context\n",
            "import android.content.Intent\n\n",
            "class GodActivity : Activity() {\n",
            "    private val spreadReceiver = object : BroadcastReceiver() {\n",
            "        override fun onReceive(c: Context?, i: Intent?) {}\n    }\n\n"]
    for m in range(methods):
        a = rng.randint(1, 999)
        body.append(f"    fun handler{m}(name: String): Int {{\n")
        for _vid, line in spread_at.get(m, []):
            body.append(line + "\n")
        if m in dup_at:
            body.append(S2_DUP_LINE + "\n")
        body.append(f"        return name.length + {a}\n    }}\n")
    body.append("}\n")
    return "".join(body)


def _manifest(count: int, vuln_lines: dict[int, str], pkg: str) -> str:
    """One component per line, all exported=false except the planted ones."""
    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
             f'    <permission android:name="{pkg}.permission.NORMAL" android:protectionLevel="normal" />',
             "    <application>",
             '        <activity android:name=".MainActivity" android:exported="true"><intent-filter>'
             '<action android:name="android.intent.action.MAIN" />'
             '<category android:name="android.intent.category.LAUNCHER" />'
             "</intent-filter></activity>"]
    for n in range(count):
        if n in vuln_lines:
            lines.append(vuln_lines[n])
            continue
        kind = KINDS[n % 3]
        lines.append(f'        <{kind} android:name=".Stub{n}{kind.capitalize()}" android:exported="false" />')
    lines += ["    </application>", "</manifest>", ""]
    return "\n".join(lines)


def _stubs(count: int, pkg: str) -> str:
    out = [f"package {pkg}\n\n", "class MainActivity : android.app.Activity()\n"]
    for n in range(count):
        kind = KINDS[n % 3]
        out.append(f"class Stub{n}{kind.capitalize()} : {STUB_BASE[kind]}\n")
    return "".join(out)


def generate(root: Path) -> dict[str, bytes]:
    """Return every generated file as repo-relative path -> bytes. Writes nothing."""
    rng = random.Random(SEED)
    s3 = _manifest(500, {252: S3_VULN_ACTIVITY, 482: S3_VULN_RECEIVER}, PKG)
    s3b = _manifest(3600, {3590: S3B_VULN_RECEIVER}, f"{PKG}.s3b")
    return {
        S1_PATH: _s1(rng).encode(),
        S2_PATH: _s2(rng).encode(),
        S3_MANIFEST: s3.encode(),
        S3_STUBS: _stubs(500, PKG).encode(),
        S3B_MANIFEST: s3b.encode(),
        S3B_STUBS: _stubs(3600, f"{PKG}.s3b").encode(),
    }


def write(root: Path) -> None:
    """Write every generated file under root."""
    for rel, data in generate(root).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def check(root: Path) -> list[str]:
    """Paths whose committed bytes differ from a fresh generation."""
    return sorted(rel for rel, data in generate(root).items()
                  if not (root / rel).exists() or (root / rel).read_bytes() != data)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="generate.py")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    if args.check:
        drift = check(root)
        sys.stdout.write(f"drift: {drift or 'none'}\n")
        return 1 if drift else 0
    write(root)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
