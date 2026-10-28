"""Read-only checks of the firmware container checksum and the LZSS copy semantics.

1. Every 0x100-byte section header carries SUM=; compare it with the plain byte sum
   of the section body.
2. Where the upstream (snapshot-copy) decode and the ff7tools (sequential-copy)
   decode differ, score which output looks like real code/text: invalid ARM words
   in .text, and printable ratio of differing bytes that sit inside ASCII context.

No codec is implemented and nothing is written except the JSON result. This is
statistical evidence about the decoded content, not a located camera decoder.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs  # noqa: E402

INPUTS = {
    "3.2-cn": ("body-3-2-cn", "92b3f1fda39e37351432d19d0167879f477eb71713a8fbc94b3ba2141ca404e4"),
    "3.1-cn": ("body-3-1-cn", "97dfa394efc91f8643c3b1a0673be2dd96590754b29080ce60d3498ebe3d15be"),
}
DECODES = {
    ".text": ("m1-3.2-cn.analysis.bin.0.00008192.decompressed", "text.mapped.candidate.bin"),
    ".rodata": ("m1-3.2-cn.analysis.bin.0.03127296.decompressed", "rodata.mapped.candidate.bin"),
    ".data": ("m1-3.2-cn.analysis.bin.0.07251968.decompressed", "data.mapped.candidate.bin"),
}
OUTPUT = ROOT / "reports/container-and-decode-check.json"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def container_sums(firmware):
    sections, offset = [], 0
    while offset < len(firmware):
        header = firmware[offset:offset + 0x100].split(b"\0")[0].decode("ascii").strip()
        length = int(re.search(r"LENGTH=(\d+)", header).group(1))
        declared = int(re.search(r"SUM=(\d+)", header).group(1))
        body = firmware[offset + 0x100:offset + 0x100 + length]
        sections.append({"header": header, "length": length, "declaredSum": declared,
                         "byteSum": sum(body), "match": declared == sum(body)})
        offset += 0x100 + length
    if offset != len(firmware):
        raise ValueError(f"Sections end at {offset}, file is {len(firmware)} bytes")
    return sections


def differing_runs(a, b):
    runs, i, n = [], 0, min(len(a), len(b))
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


def printable(data):
    return sum(1 for c in data if 32 <= c < 127 or c in (0, 9, 10, 13))


def score_section(name, snapshot, sequential):
    runs = differing_runs(snapshot, sequential)
    result = {"differingRuns": len(runs), "differingBytes": sum(j - i for i, j in runs)}
    if name == ".text":
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        words = sorted({w for i, j in runs for w in range(i & ~3, j, 4)})
        invalid = {"snapshot": 0, "sequential": 0}
        for w in words:
            for key, buf in (("snapshot", snapshot), ("sequential", sequential)):
                if not list(md.disasm(buf[w:w + 4], 0x2000 + w)):
                    invalid[key] += 1
        result.update({"wordsExamined": len(words), "invalidArmWords": invalid})
    else:
        counted = {"snapshot": 0, "sequential": 0}
        total = runs_in_text = 0
        for i, j in runs:
            context = snapshot[max(0, i - 16):i] + snapshot[j:j + 16]
            if len(context) >= 16 and printable(context) / len(context) > 0.95:
                runs_in_text += 1
                total += j - i
                counted["snapshot"] += printable(snapshot[i:j])
                counted["sequential"] += printable(sequential[i:j])
        result.update({"runsInAsciiContext": runs_in_text, "bytesInAsciiContext": total,
                       "printableRatio": {k: round(v / total, 4) for k, v in counted.items()} if total else None})
    return result


def main():
    report = {"containers": {}, "decodeSemantics3_2": {}}
    for version, (folder, expected) in INPUTS.items():
        firmware = (ROOT / "data/input" / folder / "firmware.bin").read_bytes()
        if sha256(firmware) != expected:
            raise ValueError(f"{version} input hash changed")
        report["containers"][version] = container_sums(firmware)
    for name, (snapshot_name, sequential_name) in DECODES.items():
        snapshot = (ROOT / "output/body-3-2-cn" / snapshot_name).read_bytes()
        sequential = (ROOT / "output/reference-decoded/body-3-2-cn" / sequential_name).read_bytes()
        report["decodeSemantics3_2"][name] = {
            "snapshotSha256": sha256(snapshot), "sequentialSha256": sha256(sequential),
            **score_section(name, snapshot, sequential)}
    OUTPUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for version, sections in report["containers"].items():
        print(version, "SUM match:", all(s["match"] for s in sections))
    for name, data in report["decodeSemantics3_2"].items():
        print(name, {k: v for k, v in data.items() if not k.endswith("Sha256")})


if __name__ == "__main__":
    main()
