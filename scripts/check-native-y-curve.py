"""Verify existing candidate Y-curve formatting and banked configuration writes.

Runs the original ARM code in Unicorn with synthetic 17-point curves. The
mapped destination is a memory model, not an emulated ISP or a camera screen.
No image processing algorithm, firmware patch, or transport is implemented.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

SOURCE = 0x20001000
DESCRIPTOR = 0x20002000
STACK = 0x20010000
RETURN = 0x2001ff00
CONFIG_BASE = 0x30210000
CURVE_OFFSET = 0xe4c
BANK_STRIDE = 0x30000


def main():
    path = ROOT / "output/reference-decoded/body-3-2-cn"
    sections = {name: (path / f"{name}.mapped.candidate.bin").read_bytes()
                for name in ("text", "rodata")}
    expected_hashes = {r["section"].lstrip("."): r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if r["version"] == "3.2-cn"}
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in sections.items()}
    if any(hashes[name] != expected_hashes[name] for name in sections):
        raise ValueError("Candidate source changed")
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x9b0000)
    cpu.mem_write(0x2000, sections["text"])
    cpu.mem_write(0x43f800, sections["rodata"])
    cpu.mem_map(0x20000000, 0x20000)
    cpu.mem_map(CONFIG_BASE, 0x40000)
    writes = []

    def on_write(emu, access, address, size, value, unused):
        if CONFIG_BASE <= address < CONFIG_BASE + 0x40000:
            writes.append({"address": hex(address), "size": size, "value": value})

    cpu.hook_add(UC_HOOK_MEM_WRITE, on_write)

    def execute(entry, *args):
        cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, RETURN)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
            cpu.reg_write(register, value)
        cpu.emu_start(entry, RETURN, timeout=1_000_000, count=30_000)
        if cpu.reg_read(UC_ARM_REG_PC) != RETURN or cpu.reg_read(UC_ARM_REG_SP) != STACK:
            raise AssertionError((hex(entry), "Caller stack/return not restored"))
        if cpu.reg_read(UC_ARM_REG_R0) != 0:
            raise AssertionError((hex(entry), "Unexpected native status"))

    def wire_bytes(fields):
        # Two groups of 17 halfwords; each hardware group has one padding halfword.
        return struct.pack("<18H", *fields[:17], 0) + struct.pack("<18H", *fields[17:34], 0)

    identity = [min(256 * i, 4095) for i in range(17)]
    vectors = {
        "identity": identity,
        "flat-zero": [0] * 17,
        "flat-max": [4095] * 17,
        "convex": [(4095 * i * i + 128) // 256 for i in range(17)],
        "bright-clipped": [min(2 * value, 4095) for value in identity],
        "dim-linear": [value // 2 for value in identity],
        "descending-adversarial": list(reversed(identity)),
    }
    results = []
    for name, curve in vectors.items():
        cpu.mem_write(SOURCE, struct.pack("<17H", *curve))
        for enabled in (0, 1):
            cpu.mem_write(DESCRIPTOR, bytes(140))
            execute(0x41e7d4, enabled, SOURCE, DESCRIPTOR)
            fields = list(struct.unpack("<35I", cpu.mem_read(DESCRIPTOR, 140)))
            if fields[0] != enabled or fields[34] != 0:
                raise AssertionError((name, enabled, "Flag/reserved word"))
            if enabled and (any(x > 4095 for x in fields[1:17]) or any(x > 1023 for x in fields[17:34])):
                raise AssertionError((name, "Output coefficient bounds"))
            expected = wire_bytes(fields)
            for bank in (0, 1):
                target = CONFIG_BASE + bank * BANK_STRIDE + CURVE_OFFSET
                cpu.mem_write(CONFIG_BASE, b"\xa5" * 0x40000)
                writes.clear()
                execute(0x41ef2c, DESCRIPTOR, bank)
                direct_writes = list(writes)
                if bytes(cpu.mem_read(target, 72)) != expected:
                    raise AssertionError((name, bank, "Native packing"))
                if len(direct_writes) != 18 or any(w["size"] != 4 or int(w["address"], 16) != target + 4 * i
                                                 for i, w in enumerate(direct_writes)):
                    raise AssertionError((name, bank, "Write extent/order"))
                # The wrapper includes native clearing and formatting before the same store.
                cpu.mem_write(CONFIG_BASE, b"\xa5" * 0x40000)
                writes.clear()
                execute(0x4192fc, bank, enabled, SOURCE)
                if bytes(cpu.mem_read(target, 72)) != expected or writes != direct_writes:
                    raise AssertionError((name, bank, "Full native wrapper differs"))
                memory = bytes(cpu.mem_read(CONFIG_BASE, 0x40000))
                offset = bank * BANK_STRIDE + CURVE_OFFSET
                if memory[:offset] != b"\xa5" * offset or memory[offset + 72:] != b"\xa5" * (len(memory) - offset - 72):
                    raise AssertionError((name, bank, "Other configuration bytes changed"))
                results.append({"vector": name, "enabled": enabled, "bank": bank,
                    "inputPoints": curve, "nativeFields": fields, "configurationAddress": hex(target),
                    "configurationWords": list(struct.unpack("<18I", expected)), "writes": len(writes)})
    report = {"qualification": "Candidate native configuration code on synthetic data; no ISP, display, image or camera verification.",
        "entries": {"format": "0x41e7d4", "store": "0x41ef2c", "wrapper": "0x4192fc"},
        "inputSha256": hashes, "externalCallStubs": 0, "passedConfigurations": len(results),
        "limits": ["The physical transfer/tone function of these configuration fields is not emulated.",
            "Bank numbers are not identified as preview/capture or front/back buffers.",
            "No firmware image or exposure simulation patch is generated."], "cases": results}
    (ROOT / "reports/native-y-curve-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS:", len(results), "native configurations; format/store/wrapper agree; isolated 72-byte writes; no call stubs")


if __name__ == "__main__":
    main()
