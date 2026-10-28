"""Execute a candidate message-wrapper error tail with existing Unicorn.

Status values are supplied by the harness. This checks the real ARM branch
behavior, not whether the camera actually encounters these kernel results.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_926, UC_ARM_REG_SP, UC_ARM_REG_R0

START = 0x126de8
TRAP = 0x126df8
RETURN = 0x20000100


def execute(text, status):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, (len(text)+0x2fff) & ~0xfff)
    cpu.mem_write(0x2000, text)
    cpu.mem_map(0x20000000, 0x20000)
    stack = 0x20010000
    cpu.mem_write(stack, struct.pack("<5I", 4, 5, 6, 7, RETURN))
    cpu.reg_write(UC_ARM_REG_SP, stack)
    cpu.reg_write(UC_ARM_REG_R0, status & 0xffffffff)
    state = {"suppliedKernelStatus": status, "returned": False, "trapVisits": 0}

    def hook(emu, address, size, user):
        if address == RETURN:
            state["returned"] = True
            emu.emu_stop()
        elif address == TRAP:
            state["trapVisits"] += 1
            if state["trapVisits"] == 8:
                emu.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(START, 0, timeout=1000000, count=1000)
    state["resultR0"] = cpu.reg_read(UC_ARM_REG_R0)
    return state


def main():
    text = (ROOT / "output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin").read_bytes()
    expected = next(row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if row["version"] == "3.2-cn" and row["section"] == ".text")
    if hashlib.sha256(text).hexdigest() != expected:
        raise ValueError("Candidate input hash changed")
    if struct.unpack_from("<I", text, TRAP-0x2000)[0] != 0xeafffffe:
        raise ValueError("Unexpected trap instruction")
    results = [execute(text, status) for status in (0, -43, -18, -42, -17)]
    for result in results:
        status = result["suppliedKernelStatus"]
        if status in (0, -43):
            if not result["returned"] or result["trapVisits"] or result["resultR0"] != (0 if status == 0 else 2):
                raise AssertionError("Unexpected handled status")
        elif result["returned"] or result["trapVisits"] != 8:
            raise AssertionError("Unexpected unhandled status")
    report = {"qualification": "Isolated candidate error-tail behavior; not a reproduced camera failure or a fix.",
        "engine": "Unicorn 2.1.4 ARM926", "textSha256": expected,
        "entry": hex(START), "selfBranch": hex(TRAP), "passedCases": len(results),
        "results": results, "limits": [
            "Kernel statuses and a saved return frame are supplied; the kernel and message queue are not executed.",
            "No evidence yet that these errors occur in the user's camera or explain its full freezes.",
            "Candidate decoder compatibility and runtime address mapping are not camera verified.",
            "No code bytes changed, no error ignored, no camera access or firmware image output."]}
    old_text = (ROOT / "output/reference-decoded/body-3-1-cn/text.mapped.candidate.bin").read_bytes()
    old_hash = next(row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if row["version"] == "3.1-cn" and row["section"] == ".text")
    if hashlib.sha256(old_text).hexdigest() != old_hash:
        raise ValueError("3.1 candidate input hash changed")
    needle = text[START-0x2000:TRAP-0x2000+4]
    matches = []
    cursor = 0
    while (cursor := old_text.find(needle, cursor)) >= 0:
        matches.append(hex(cursor+0x2000))
        cursor += 1
    report["threeOneIdenticalTailMatches"] = matches
    (ROOT / "reports/message-error-path-results.json").write_text(json.dumps(report,indent=2)+"\n")
    for result in results:
        print(result)
    print("PASS: 5 isolated error-tail cases")
    print("3.1 identical tail matches:", matches)


if __name__ == "__main__":
    main()
