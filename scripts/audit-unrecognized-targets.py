"""Capstone evidence for every direct-call target missing from the catalog.

Uses existing catalog and candidate inputs; does not create Ghidra functions.
Sequential/snapshot equality is checked per evidence window, not assumed.
"""
from pathlib import Path
import csv
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM


def main():
    text = (ROOT / "output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin").read_bytes()
    expected = next(r["mappedSha256"] for r in json.loads((ROOT / "reports/reference-decode-results.json").read_text())[
        "results"] if r["version"] == "3.2-cn" and r["section"] == ".text")
    if hashlib.sha256(text).hexdigest() != expected:
        raise ValueError("Candidate text hash mismatch")
    upstream = json.loads((ROOT / "reports/container-and-decode-check.json").read_text())["decodeSemantics3_2"][".text"]
    # Find the existing upstream snapshot artifact by its recorded hash.
    candidates = list((ROOT / "output/body-3-2-cn").glob("*.decompressed"))
    snapshot = next((p.read_bytes() for p in candidates if hashlib.sha256(p.read_bytes()).hexdigest() == upstream["snapshotSha256"]), None)
    if snapshot is None:
        raise ValueError("Cannot locate verified snapshot decode")
    with (ROOT / "output/code-map/unrecognized-call-targets.tsv").open(encoding="utf-8", newline="") as stream:
        targets = list(csv.DictReader(stream, delimiter="\t", quoting=csv.QUOTE_NONE))
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    results = []
    for row in targets:
        address = int(row["target"], 16)
        offset = address - 0x2000
        if not 0 <= offset <= len(text) - 64:
            raise ValueError("Target evidence window is outside candidate .text")
        raw = text[offset:offset + 64]
        instructions = list(cs.disasm(raw, address))
        calls = []
        for value in row["callsites"].split(";"):
            site = int(value, 16)
            if not 0x2000 <= site <= 0x2000 + len(text) - 4:
                raise ValueError("Callsite is outside candidate .text")
            instruction = next(cs.disasm(text[site - 0x2000:site - 0x2000 + 4], site))
            if instruction.mnemonic not in ("bl", "blx") or instruction.op_str != f"#{address:#x}":
                raise ValueError("Catalog callsite does not branch to target")
            calls.append(dict(address=hex(site), raw=instruction.bytes.hex(), assembly=f"{instruction.mnemonic} {instruction.op_str}"))
        if len(calls) != int(row["callsite_count"]):
            raise ValueError("Catalog callsite count differs from the recorded callsites")
        results.append(dict(target=hex(address), catalogCalls=int(row["callsite_count"]), callsites=calls,
                            evidenceBytes=raw.hex(), snapshotWindowIdentical=raw == snapshot[offset:offset + len(raw)],
                            disassembly=[dict(address=hex(i.address), raw=i.bytes.hex(), assembly=f"{i.mnemonic} {i.op_str}") for i in instructions]))
    report = dict(passed=True, textSha256=expected, targets=results,
                  qualification="All five missing direct-call entries have raw instruction evidence; no ABI or reachability inference from a prologue alone.",
                  limitations=["64-byte windows may contain several compiler outline fragments or inline data.",
                               "No new functions or source project changes; not complete indirect-call resolution.",
                               "Register and CPSR effects of these fragments require caller-specific analysis."])
    destination = ROOT / "reports/unrecognized-target-audit-2026-10-29.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(results)} targets; {sum(len(r['callsites']) for r in results)} verified direct callsites")


if __name__ == "__main__":
    main()
