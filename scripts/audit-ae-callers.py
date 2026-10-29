"""Cross-check AE direct-call candidates over every aligned original ARM word.

Capstone interprets the instructions. This avoids stopping a linear decode at
an inline data gap, but raw candidates still do not prove runtime reachability.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM


def main():
    text = (ROOT / "output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin").read_bytes()
    expected_sha = next(r["mappedSha256"] for r in json.loads((ROOT / "reports/reference-decode-results.json").read_text())[
        "results"] if r["version"] == "3.2-cn" and r["section"] == ".text")
    assert hashlib.sha256(text).hexdigest() == expected_sha
    expected = {0x361ad4: [0x35a0ac, 0x35b2a0, 0x35b3e8, 0x35b500, 0x360338, 0x361c70, 0x362084],
                0x361c0c: [0x358a7c, 0x359fe8]}
    results = {address: [] for address in expected}
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for offset in range(0, len(text) - 3, 4):
        # Only prefilter A32 BL encodings; Capstone checks target and condition.
        word = struct.unpack_from("<I", text, offset)[0]
        if word & 0x0f000000 != 0x0b000000:
            continue
        for ins in cs.disasm(text[offset:offset + 4], offset + 0x2000):
            for address in expected:
                if ins.mnemonic.startswith("bl") and ins.op_str == f"#{address:#x}":
                    results[address].append(dict(callsite=hex(ins.address), raw=ins.bytes.hex(), assembly=f"{ins.mnemonic} {ins.op_str}"))
    for address, calls in expected.items():
        assert [int(r["callsite"], 16) for r in results[address]] == calls
    report = dict(passed=True, textSha256=expected_sha, alignedWordsScanned=len(text) // 4,
                  directCalls={hex(a): rows for a, rows in results.items()},
                  limits=["Aligned A32 BL candidates only; no indirect calls, Thumb or other executable payloads.",
                          "Raw candidates can in general be data; the listed callsites require instruction-context review.",
                          "Seven cfg-filler callsites occur in six catalog functions; this is not seven independent business modes."])
    (ROOT / "reports/ae-caller-audit-2026-10-29.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("PASS: seven cfg-fill callsites, two configuration-stage callsites; full aligned-word cross-check")


if __name__ == "__main__":
    main()
