"""Resolve two candidate property dispatches by executing their real ARM code.

Uses existing Unicorn and Capstone. Stops before the selected property handler;
no peripheral, network, camera command or modified firmware is involved.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_CPU_ARM_926, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM


def resolve(text, rodata, start, stop, property_id, value):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x9b0000)
    cpu.mem_write(0x2000, text)
    cpu.mem_write(0x43f800, rodata)
    cpu.mem_map(0x20000000, 0x20000)
    cpu.reg_write(UC_ARM_REG_SP, 0x20010000)
    cpu.reg_write(UC_ARM_REG_R0, property_id)
    cpu.reg_write(UC_ARM_REG_R1, value)
    state = {"stopped": False, "instructions": 0, "target": None}

    def hook(emu, address, size, user):
        state["instructions"] += 1
        if address == stop:
            state["target"] = hex(emu.reg_read(UC_ARM_REG_R0))
            state["stopped"] = True
            emu.emu_stop()

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(start, 0, timeout=1000000, count=10000)
    if not state["stopped"]:
        raise AssertionError("Did not reach the checked dispatch boundary")
    target = int(state["target"], 16)
    if not (0x2000 <= target < 0x2000 + len(text)) or target % 4:
        raise AssertionError("Resolved target is outside candidate ARM text")
    return state


def main():
    source = ROOT / "output/reference-decoded/body-3-2-cn"
    text = (source / "text.mapped.candidate.bin").read_bytes()
    rodata = (source / "rodata.mapped.candidate.bin").read_bytes()
    expected = {row["section"]: row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if row["version"] == "3.2-cn"}
    for name, data in ((".text", text), (".rodata", rodata)):
        if hashlib.sha256(data).hexdigest() != expected[name]:
            raise ValueError("Candidate input hash changed")
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    functions = (("property-store", 0x15a7e0, 0x15a808), ("property-apply", 0x15c5bc, 0x15c5f0))
    properties = (("ISO", 5), ("EV", 0x12), ("shutter", 0x13), ("aperture", 0x14))
    results = []
    targets = []
    for role, start, stop in functions:
        instruction = next(cs.disasm(text[stop-0x2000:stop-0x2000+4], stop))
        if (instruction.mnemonic, instruction.op_str) != ("mov", "pc, r0"):
            raise AssertionError("Unexpected boundary instruction")
        for name, property_id in properties:
            resolved = set()
            for value in (0, 3, 13):
                state = resolve(text, rodata, start, stop, property_id, value)
                resolved.add(state["target"])
                results.append({"role": role, "start": hex(start), "stop": hex(stop),
                    "property": name, "propertyId": property_id, "testValue": value, **state})
            if len(resolved) != 1:
                raise AssertionError("Dispatch target depends on an unexpected test value")
            target = resolved.pop()
            targets.append(target)
            print(role, name, hex(property_id), "->", target)
    report = {"qualification": "Candidate static dispatch resolution only; no target handler or camera hardware executed.",
        "engine": "Unicorn 2.1.4 ARM926; boundaries checked with Capstone", "passedCases": len(results),
        "propertyNameBasis": "HTTP action IDs -> 23-entry table -> internal property IDs; not sensor register names.",
        "limits": ["Dispatch role names are analysis labels; handler behavior must be verified separately.",
                   "Candidate decoding and runtime mapping remain unverified on camera.",
                   "Does not test true ISO/shutter values, exposure simulation, performance or stability."],
        "results": results}
    (ROOT / "reports/exposure-dispatch-results.json").write_text(json.dumps(report, indent=2)+"\n")
    (ROOT / "config/exposure-dispatch-targets.txt").write_text(
        "# Case-block addresses, not function entries; inspect instructions without defining new functions.\n" +
        "\n".join(dict.fromkeys(targets))+"\n")
    print("PASS:", len(results), "isolated dispatch cases")


if __name__ == "__main__":
    main()
