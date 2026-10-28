"""Execute the unchanged candidate curve-mode selector with existing Unicorn.

Test glue only: synthetic context values and independent expected mode cases.
Does not emulate the ISP or identify a mode as preview/capture.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

CTX = 0x20001000
STACK = 0x20010000
RETURN = 0x2001ff00
ENTRY = 0x3d613c
LOOKUP = 0x8742d2


def main():
    path = ROOT / "output/reference-decoded/body-3-2-cn"
    source = {name: (path / f"{name}.mapped.candidate.bin").read_bytes()
              for name in ("text", "rodata", "data")}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in source.items()}
    expected = {r["section"].lstrip("."): r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if r["version"] == "3.2-cn"}
    if hashes != expected:
        raise ValueError("Candidate section hash changed")
    lookup = list(source["rodata"][LOOKUP - 0x43f800:LOOKUP - 0x43f800 + 12])
    providers = struct.unpack_from("<10I", source["data"], 0xc09e360c - 0xc09b0000)
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x9b0000)
    cpu.mem_write(0x2000, source["text"])
    cpu.mem_write(0x43f800, source["rodata"])
    cpu.mem_map(0x20000000, 0x20000)
    reads = []

    def read(emu, access, address, size, value, unused):
        if CTX <= address < CTX + 0x200 or LOOKUP <= address < LOOKUP + 12:
            reads.append({"address": hex(address), "bytes": size})
    cpu.hook_add(UC_HOOK_MEM_READ, read)
    cases = []

    def check(path_value, byte120, word130, wanted, read_fields):
        cpu.mem_write(CTX, bytes(0x200))
        cpu.mem_write(CTX + 0x120, bytes([byte120]))
        cpu.mem_write(CTX + 0x130, struct.pack("<I", word130))
        cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, RETURN)
        cpu.reg_write(UC_ARM_REG_R0, path_value)
        cpu.reg_write(UC_ARM_REG_R1, CTX)
        reads.clear()
        cpu.emu_start(ENTRY, RETURN, timeout=1_000_000, count=100)
        result = cpu.reg_read(UC_ARM_REG_R0)
        context_reads = [r for r in reads if CTX <= int(r["address"], 16) < CTX + 0x200]
        if result != wanted or context_reads != read_fields:
            raise AssertionError((path_value, byte120, word130, result, wanted, reads))
        if cpu.reg_read(UC_ARM_REG_PC) != RETURN or cpu.reg_read(UC_ARM_REG_SP) != STACK:
            raise AssertionError("Native return/stack changed")
        cases.append({"path": hex(path_value), "contextByte120": byte120,
                      "contextWord130": word130, "modeIndex": result,
                      "providerAddress": hex(providers[result]), "dataReads": list(reads)})

    # Independent expected branches, including the initialized constant-table cases.
    for value in range(256):
        check(1, value, 0xffffffff, 2 if value == 1 else 1,
              [{"address": hex(CTX + 0x120), "bytes": 1}])
    selected = {2: 5, 3: 4, 5: 9, 6: 8, 7: 7}
    for value in [*range(16), 0x7fffffff, 0x80000000, 0xffffffff]:
        check(3, 1, value, selected.get(value, 6),
              [{"address": hex(CTX + 0x130), "bytes": 4}])
    for path_value in (0, 2, 4, 0x15, 0x16, 0x17, 0x7fffffff, 0x80000000, 0xffffffff):
        check(path_value, 1, 5, 3, [])
    report = {"qualification": "Original candidate ARM instructions on synthetic contexts; not camera execution or preview/capture identification.",
              "entry": hex(ENTRY), "tailHelper": "0x360150", "externalCallStubs": 0,
              "inputSha256": hashes, "passedCases": len(cases),
              "constantTableAddress": hex(LOOKUP), "constantTableBytes": lookup,
              "providerTableAddress": "0xc09e360c", "providerTable": [hex(p) for p in providers],
              "observedModeIndices": sorted({c["modeIndex"] for c in cases}), "cases": cases}
    (ROOT / "reports/native-curve-mode-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(cases)} native selector cases; exact context reads; mode indices 1..9; no call stubs")


if __name__ == "__main__":
    main()
