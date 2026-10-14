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
print("CLI JSON smoke: single/compare produce exactly one JSON document; invalid combinations rejected.")
PY
