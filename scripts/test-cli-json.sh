#!/usr/bin/env bash
# Regression gate: machine-readable CLI invocations return ONE JSON document,
# even in comparison mode. No PCAP sample containing customer traffic is used.
set -euo pipefail

if [[ $# != 1 || ! -x "$1" ]]; then
  echo 'usage: scripts/test-cli-json.sh <executable-path>' >&2
  exit 2
fi

binary="$(realpath "$1")"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

python3 - "$binary" "$tmp" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

binary = sys.argv[1]
tmp = Path(sys.argv[2])
pcap = tmp / "minimal.pcap"

header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
frame = bytearray(54)
frame[0:6] = b"\xff" * 6
frame[6:12] = bytes.fromhex("001122334455")
frame[12:14] = bytes.fromhex("0800")
frame[14] = 0x45
frame[16:18] = struct.pack("!H", 40)
frame[22:24] = bytes((64, 6))
frame[26:30] = bytes((192, 168, 1, 10))
frame[30:34] = bytes((10, 0, 0, 1))
frame[34:36] = struct.pack("!H", 12345)
frame[36:38] = struct.pack("!H", 443)
frame[46:48] = bytes((0x50, 0x02))
record = struct.pack("<IIII", 1728960000, 0, len(frame), len(frame))
pcap.write_bytes(header + record + frame)

def check_json(flags):
    result = subprocess.run(
        [binary, *flags],
        cwd=tmp, capture_output=True, text=True, timeout=40, check=False
    )
    if result.returncode != 0:
        raise AssertionError(f"{flags}: exit {result.returncode}: {result.stderr}")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise AssertionError(f"{flags}: stdout is not exactly one JSON document: {result.stdout[:500]!r}") from exc

single = check_json(["-json", "-no-external-lookup", str(pcap)])
assert single["capture_quality"]["packet_count"] == 1
assert single["capture_quality"]["sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()

comparison = check_json(["-compare", "-json", "-no-external-lookup", str(pcap), str(pcap)])
assert comparison["total_packets_a"] == 1, comparison
assert comparison["total_packets_b"] == 1, comparison

invalid = subprocess.run(
    [binary, "-json", "-csv", "report.csv", str(pcap)],
    cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
)
assert invalid.returncode != 0, "ambiguous JSON + CSV invocation unexpectedly succeeded"
assert invalid.stdout == "", f"unexpected output on rejected invocation: {invalid.stdout!r}"
assert "cannot be combined" in invalid.stderr, invalid.stderr

# Bad arguments, including flags rejected before parsing, must never print
# human usage on stdout when the caller requested machine-readable output.
for flags in (["-json"], ["-json", "-unknown-flag"], ["-unknown-flag", "-json"]):
    failed = subprocess.run(
        [binary, *flags],
        cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
    )
    assert failed.returncode != 0, f"{flags} unexpectedly succeeded"
    assert failed.stdout == "", f"{flags} contaminated JSON stdout: {failed.stdout[:500]!r}"
    assert failed.stderr, f"{flags} did not report a diagnostic on stderr"

# A second PCAP that contains one valid record and then an incompletely
# captured record must not yield a plausible comparison over its prefix.
truncated = tmp / "incomplete.pcap"
truncated.write_bytes(
    pcap.read_bytes() + struct.pack("<IIII", 1728960001, 0, 54, 54) + b"partial"
)
bad_compare = subprocess.run(
    [binary, "-compare", "-json", str(pcap), str(truncated)],
    cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
)
assert bad_compare.returncode != 0, "corrupt comparison capture incorrectly accepted"
assert bad_compare.stdout == "", "corrupt comparison emitted misleading JSON"
assert "invalid packet record" in bad_compare.stderr, bad_compare.stderr

# Header-only classic PCAP is structurally valid but has zero observations.
# Neither side of a comparison may silently be an empty capture.
header_only = tmp / "header-only.pcap"
header_only.write_bytes(header)
for before, after in ((pcap, header_only), (header_only, pcap)):
    rejected = subprocess.run(
        [binary, "-compare", "-json", str(before), str(after)],
        cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
    )
    assert rejected.returncode != 0, "header-only comparison unexpectedly succeeded"
    assert rejected.stdout == "", rejected.stdout
    assert ("no packet records" in rejected.stderr or "no packets present" in rejected.stderr), rejected.stderr

# Only terminal text and JSON are currently supported for comparison mode.
# Do not pretend a requested HTML/CSV/PDF export succeeded while ignoring it.
for export in (["-html", "report.html"], ["-csv", "report.csv"], ["-pdf", "report.pdf"], ["-simple"]):
    flags = ["-compare", *export, str(pcap), str(pcap)]
    rejected = subprocess.run(
        [binary, *flags],
        cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
    )
    assert rejected.returncode != 0, f"ignored comparison export unexpectedly succeeded: {flags}"
    assert rejected.stdout == "", f"comparison export contaminated stdout: {rejected.stdout[:300]!r}"
    assert "-compare does not support" in rejected.stderr, (flags, rejected.stderr)

# Comparison is intentionally not a filtered single-capture analysis. Every
# explicitly supplied analysis-only flag must fail closed instead of silently
# emitting an unfiltered comparison that violates the caller's intent.
for extra in (
    ["-src-ip", "192.0.2.1"],
    ["-dst-ip", "198.51.100.1"],
    ["-service", "dns"],
    ["-protocol", "tcp"],
    ["-config", "performance"],
    ["-qos-analysis"],
    ["-show-handshakes"],
    ["-handshake-timeout", "3"],
):
    flags = ["-compare", "-json", *extra, str(pcap), str(pcap)]
    rejected = subprocess.run(
        [binary, *flags],
        cwd=tmp, capture_output=True, text=True, timeout=40, check=False,
    )
    assert rejected.returncode != 0, f"ignored filter unexpectedly accepted: {flags}"
    assert rejected.stdout == "", f"comparison filter polluted JSON stdout: {rejected.stdout[:300]!r}"
    assert "-compare does not support" in rejected.stderr, (flags, rejected.stderr)

web_compare = subprocess.run(
    [binary, "-compare", "-web", str(pcap), str(pcap)],
    cwd=tmp, capture_output=True, text=True, timeout=10, check=False,
)
assert web_compare.returncode != 0 and "-compare cannot be used with -web" in web_compare.stderr
assert web_compare.stdout == ""

help_text = subprocess.run([binary, "-help"], cwd=tmp, capture_output=True,
                           text=True, timeout=10, check=False)
assert help_text.returncode == 0
assert "-html report.html -json -csv" not in help_text.stdout
assert "tracesleuth -json capture.pcap" in help_text.stdout
assert "-no-external-lookup" in help_text.stdout
assert "github.com/DanielDietz-de/TraceSleuth" in help_text.stdout
assert "github.com/gocisse/tracesleuth" not in help_text.stdout
assert "tracesleuth analyze " not in help_text.stdout

print("CLI smoke: JSON/compare reject corrupt or empty captures, invalid flags, and misleading help.")
PY
