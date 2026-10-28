"""Execute an existing candidate ARM delta/quantization routine, without stubs.

Unicorn supplies the CPU; the unchanged candidate supplies all arithmetic,
table traversal, validation and division. Synthetic bounds are NOT a sensor,
measured camera state, or proof of the physical meaning of its input.
"""
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

ENTRY = 0x360f4c
TABLE = 0x20001000
CONFIG = 0x20002000
STACK = 0x20010000
RETURN = 0x2001ff00


def nearest_positive(value):
    return (value.numerator * 2 + value.denominator) // (value.denominator * 2)


def reference(measured, lower, upper):
    delta = measured - min(max(measured, lower), upper)
    thirds = nearest_positive(Fraction(3 * abs(delta), 1024))
    tenths = nearest_positive(Fraction(10 * thirds, 3))
    return -tenths if delta < 0 else tenths


def main():
    source = ROOT / "output/reference-decoded/body-3-2-cn"
    sections = {name: (source / f"{name}.mapped.candidate.bin").read_bytes()
                for name in ("text", "rodata")}
    expected_hashes = {row["section"].lstrip("."): row["mappedSha256"] for row in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if row["version"] == "3.2-cn"}
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in sections.items()}
    if any(hashes[name] != expected_hashes[name] for name in sections):
        raise ValueError("Candidate source changed")
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x9b0000)
    cpu.mem_write(0x2000, sections["text"])
    cpu.mem_write(0x43f800, sections["rodata"])
    cpu.mem_map(0x20000000, 0x20000)
    cpu.mem_map(0xc1400000, 0x200000)

    def execute(measured, lower, upper, mode=0, sentinel=0, null_table=False, null_config=False):
        table = bytearray(80)
        struct.pack_into("<h", table, 0, upper)
        struct.pack_into("<hh", table, 20, lower, 1)
        cpu.mem_write(TABLE, bytes(table))
        config = bytearray(0xac)
        struct.pack_into("<ii", config, 0x1c, mode, 0)
        struct.pack_into("<i", config, 0x40, sentinel)
        cpu.mem_write(CONFIG, bytes(config))
        cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, RETURN)
        cpu.reg_write(UC_ARM_REG_R0, measured & 0xffffffff)
        cpu.reg_write(UC_ARM_REG_R1, 0 if null_table else TABLE)
        cpu.reg_write(UC_ARM_REG_R2, 0 if null_config else CONFIG)
        cpu.emu_start(ENTRY, RETURN, timeout=1_000_000, count=20_000)
        if cpu.reg_read(UC_ARM_REG_PC) != RETURN or cpu.reg_read(UC_ARM_REG_SP) != STACK:
            raise AssertionError("Native routine did not return with its caller stack intact")
        value = cpu.reg_read(UC_ARM_REG_R0)
        return value - 0x100000000 if value & 0x80000000 else value

    inputs = [-32768, -8192, -4096, -3072, -1536, -1024, -854, -853, -513, -512,
              -511, -342, -341, -171, -170, -1, 0, 1, 170, 171, 341, 342, 511,
              512, 513, 853, 854, 1024, 1536, 3072, 4096, 8192, 32767]
    results = []
    for lower, upper in ((0, 0), (-1024, 2048), (-3072, -1024), (1024, 3072)):
        for measured in sorted(set(inputs + [lower - 1, lower, lower + 1, upper - 1, upper, upper + 1])):
            actual = execute(measured, lower, upper)
            expected = reference(measured, lower, upper)
            if actual != expected:
                raise AssertionError((measured, lower, upper, actual, expected))
            results.append({"input": measured, "lower": lower, "upper": upper, "output": actual})
    guards = []
    for options in ({"mode": 5}, {"mode": 1, "sentinel": -1}, {"null_table": True}, {"null_config": True}):
        actual = execute(4096, 0, 0, **options)
        if actual != 0:
            raise AssertionError((options, actual))
        guards.append({"options": options, "output": actual})
    # Exercise the actual caller as well: it reads an input scalar and bounds
    # from RAM, calls both native result routines, and writes two output words.
    producer_results = []
    for case in results:
        table = bytearray(80)
        struct.pack_into("<h", table, 0, case["upper"])
        struct.pack_into("<hh", table, 20, case["lower"], 1)
        cpu.mem_write(0xc1470010, bytes(table))
        cpu.mem_write(0xc159d74c, struct.pack("<h", case["input"]))
        for offset in (0x4c, 0x5c, 0x70):
            cpu.mem_write(0xc1469694 + offset, bytes(4))
        cpu.mem_write(TABLE + 0x100, b"\xa5" * 8)
        cpu.reg_write(UC_ARM_REG_CPSR, 0x13)
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, RETURN)
        cpu.reg_write(UC_ARM_REG_R0, TABLE + 0x100)
        cpu.reg_write(UC_ARM_REG_R1, TABLE + 0x104)
        cpu.emu_start(0x36102c, RETURN, timeout=1_000_000, count=20_000)
        if cpu.reg_read(UC_ARM_REG_PC) != RETURN or cpu.reg_read(UC_ARM_REG_SP) != STACK:
            raise AssertionError("Native producer did not restore its caller stack")
        indicator, delta = struct.unpack("<ii", cpu.mem_read(TABLE + 0x100, 8))
        if cpu.reg_read(UC_ARM_REG_R0) != 0 or delta != case["output"]:
            raise AssertionError(("native producer", case, indicator, delta))
        producer_results.append({"input": case["input"], "lower": case["lower"],
                                 "upper": case["upper"], "indicator": indicator, "delta": delta})
    report = {"qualification": "Candidate native arithmetic with synthetic data; no camera or hardware emulation.",
        "entry": hex(ENTRY), "engine": "Unicorn 2.1.4 ARM926", "inputSha256": hashes,
        "externalCallStubs": 0, "formula": "delta = input - clamp(input, lower, upper); quantize delta/1024 to nearest third, then nearest tenth; ties away from zero",
        "passedArithmeticCases": len(results), "passedGuardCases": len(guards),
        "producerEntry": "0x36102c", "passedProducerCases": len(producer_results),
        "physicalMeaningNotProven": ["Origin of the input scalar and bounds", "Target-minus-metering exposure interpretation and direction", "Actual preview sensor exposure or gain", "Safe firmware repack or patch"],
        "arithmetic": results, "guards": guards, "producer": producer_results}
    (ROOT / "reports/native-exposure-delta-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS:", len(results), "arithmetic,", len(guards), "guard and",
          len(producer_results), "full producer cases; no call stubs")


if __name__ == "__main__":
    main()
