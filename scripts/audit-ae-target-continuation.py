"""Execute original AE gates, the next target stage, and complete output copy.

Reuses the existing Unicorn fixture. No call stubs, camera or patched image.
Synthetic states prove conditional code behavior, not the camera's live path.
"""
from pathlib import Path
import hashlib
import importlib.util
import itertools
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ae_fixture", ROOT / "scripts/check-exposure-preview-patch.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)
OUT = 0x20028000
TARGET_STORE = 0x20029000
LIVE_STATE = 0xc14707e0
PROGRAM = 0xc159d7a8


def gate_case(flag, state_mode):
    cpu, status = fx.machine(False, [(fx.STATE, fx.STATE + 0x100), (fx.SP - 0x1000, fx.SP + 8)])
    fx.put(cpu, fx.SP, fx.SNAP)
    fx.put(cpu, fx.SP + 4, fx.STATE)
    cpu.mem_write(fx.CFG + 0x57, bytes([flag]))
    cpu.mem_write(fx.STATE + 0xe0, bytes([state_mode]))
    cpu.reg_write(fx.UC_ARM_REG_R0, 1)
    cpu.reg_write(fx.UC_ARM_REG_R1, fx.SNAP)
    cpu.reg_write(fx.UC_ARM_REG_R2, fx.CFG)
    cpu.reg_write(fx.UC_ARM_REG_R3, OUT)
    reached = []

    def boundary(c, address, size, user):
        if address in (0x362bbc, 0x364504):
            reached.append(address)
            status["finished"] = True
            c.emu_stop()

    cpu.hook_add(fx.UC_HOOK_CODE, boundary)
    fx.execute(cpu, status, 0x365344)
    expected = 0x362bbc if flag == 0 or state_mode == 2 else 0x364504
    assert reached == [expected], (flag, state_mode, reached)
    return dict(cfg57=flag, stateE0=state_mode, reached=hex(reached[0]))


def target_case(base, compensation):
    cpu, status = fx.machine(False, [(fx.STATE, fx.STATE + 0x100), (fx.SP - 0x1000, fx.SP),
                                    (fx.SNAP, fx.SNAP + 0x300), (TARGET_STORE, TARGET_STORE + 4),
                                    (0xc146f500, 0xc146f620), (0xc159d71c, 0xc159d724)])
    fx.put(cpu, fx.CFG + 0x10, base)
    fx.put(cpu, fx.CFG + 0x30, compensation)
    fx.put(cpu, fx.CFG + 0x78, fx.SNAP)
    fx.put(cpu, fx.SNAP + 0x280, TARGET_STORE)
    for register, value in ((fx.UC_ARM_REG_R0, 1), (fx.UC_ARM_REG_R1, fx.CFG),
                            (fx.UC_ARM_REG_R2, fx.SNAP), (fx.UC_ARM_REG_R3, fx.STATE)):
        cpu.reg_write(register, value)
    # Continue through native smoothing, normalization, and all target stores.
    fx.execute(cpu, status, 0x362bbc, 0x362c0c)
    factor = struct.unpack_from("<I", fx.RODATA, 0x860d08 - 0x43f800 + (compensation + 90) * 4)[0]
    first = base * factor // 10000
    expected = first if first <= base * 2 else base * 2 + ((first - base * 2) * 11 >> 4)
    actual = fx.word(cpu, fx.STATE + 0xb8)
    assert actual == expected
    assert fx.word(cpu, fx.SNAP + 0x228) == actual == fx.word(cpu, TARGET_STORE)
    return dict(base=base, compensationTenths=compensation, targetBeforeNextStage=first, targetAfterNextStage=actual)


def program_case(target, field4, field6):
    allowed = [(LIVE_STATE, LIVE_STATE + 0x200), (PROGRAM, PROGRAM + 0x40),
               (0xc146f500, 0xc146f620), (fx.SP - 0x1000, fx.SP + 0x100)]
    cpu, status = fx.machine(False, allowed)
    fx.put(cpu, LIVE_STATE + 0xb8, target)
    cpu.mem_write(PROGRAM + 4, struct.pack("<hh", field4, field6))
    fx.put(cpu, 0x30100004, 1199 << 16)
    fx.put(cpu, 0x30100020, 1000 << 16)
    fx.put(cpu, 0xc09d9804, 1)
    for register, value in ((fx.UC_ARM_REG_R4, PROGRAM), (fx.UC_ARM_REG_R5, LIVE_STATE),
                            (fx.UC_ARM_REG_R6, fx.CFG), (fx.UC_ARM_REG_R7, 0xc14708d0)):
        cpu.reg_write(register, value)
    fx.execute(cpu, status, 0x365410, 0x365448)
    triple = [fx.word(cpu, LIVE_STATE + off) for off in (0x38, 0x3c, 0x40)]
    assert triple == [fx.word(cpu, LIVE_STATE + off) for off in (0x2c, 0x30, 0x34)]
    return dict(target=target, programField4=field4, programField6=field6, outputTriple=triple)


def output_case(compensation):
    cpu, status = fx.machine(False, [(OUT, OUT + 0x80), (fx.SP - 0x1000, fx.SP)])
    source = bytes((i * 17 + 3) & 255 for i in range(0x100))
    cpu.mem_write(fx.STATE, source)
    cpu.mem_write(OUT, bytes([0xcc]) * 0x80)
    fx.put(cpu, fx.CFG + 0x30, compensation)
    for register, value in ((fx.UC_ARM_REG_R0, fx.CFG), (fx.UC_ARM_REG_R1, OUT),
                            (fx.UC_ARM_REG_R2, fx.SNAP), (fx.UC_ARM_REG_R3, fx.STATE)):
        cpu.reg_write(register, value)
    reads = []

    def read_hook(c, access, address, size, value, user):
        if fx.CFG <= address < fx.CFG + 0x80:
            reads.append(hex(address))

    cpu.hook_add(fx.UC_HOOK_MEM_READ, read_hook)
    fx.execute(cpu, status, 0x364504)
    result = bytes(cpu.mem_read(OUT, 0x80))
    assert cpu.reg_read(fx.UC_ARM_REG_SP) == fx.SP and not reads
    assert result[:36] == source[0x2c:0x50]
    for target, start in ((0x24, 0xc4), (0x28, 0xc8), (0x2c, 8), (0x30, 0x20), (0x34, 0xbc), (0x38, 0xb4)):
        assert result[target:target + 4] == source[start:start + 4]
    assert result[0x48:] == bytes([0xcc]) * (0x80 - 0x48)
    return dict(compensationTenths=compensation, cfgReads=reads, outputHex=result.hex(), stackRestored=True)


def main():
    expected = {r["section"].lstrip("."): r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"] if r["version"] == "3.2-cn"}
    actual = {name: hashlib.sha256(raw).hexdigest() for name, raw in (("text", fx.TEXT), ("rodata", fx.RODATA), ("data", fx.DATA))}
    assert actual == expected
    gates = [gate_case(a, b) for a, b in itertools.product((0, 1, 2, 255), repeat=2)]
    targets = [target_case(base, comp) for base, comp in itertools.product((100, 3869, 100000), (-50, -33, -20, -10, 0, 10, 20, 33, 50))]
    programs = [program_case(target, a, b) for (a, b), target in itertools.product(
        ((4000, 100), (8000, 200), (2000, 400)), (0, 100, 3869, 13057))]
    for fields in ((4000, 100), (8000, 200), (2000, 400)):
        assert len({tuple(r["outputTriple"]) for r in programs if (r["programField4"], r["programField6"]) == fields}) == 1
    assert len({tuple(r["outputTriple"]) for r in programs}) == 3
    outputs = [output_case(comp) for comp in (-50, 0, 50)]
    assert len({row["outputHex"] for row in outputs}) == 1
    report = dict(passed=True, inputHashes=actual, externalCallStubs=0, gateCases=gates, targetCases=targets, programCases=programs, outputCases=outputs,
        proved=["The original gate can select a complete output-copy path without target recomputation.",
                "On that path, the complete original 0x364504 function does not read cfg+0x30 and copies the supplied state.",
                "With the documented synthetic zero-based normalization state, native target normalization and all three target stores preserve the changed target.",
                "The next original target stage compresses positive targets above twice base; it does not always erase compensation.",
                "The original 0x365410..0x365448 output recomputation is unchanged when only state+0xb8 varies, but changes when the program fields vary."],
        limits=["All configuration and algorithm state inputs are synthetic, not a camera memory trace.",
                "Target execution stops at 0x362c0c after 0x35d280 and target stores, before the rest of AE and hardware.",
                "The program recomputation region is tested separately with synthetic state and does not prove runtime ordering or field physical units.",
                "No claim that the real camera selected the bypass branch; no exposure patch or firmware produced."])
    path = ROOT / "reports/ae-target-continuation-2026-10-29.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(gates)} native gates, {len(targets)} extended targets, {len(programs)} program triples, {len(outputs)} complete output copies; no call stubs")


if __name__ == "__main__":
    main()
