"""Execute the unchanged candidate queue-send routine on synthetic quiescent RAM.

No external calls are stubbed: ARM interrupt-mask helpers run in Unicorn. There
are no real tasks, interrupts, devices or camera queue IDs in this experiment.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_CPU_ARM_926, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

BASE = 0xc15d5cfc
NODE = 0x20001000
STACK = 0x20010000
RETURN = 0x2001ff00


def main():
    text = (ROOT / "output/reference-decoded/body-3-2-cn/text.mapped.candidate.bin").read_bytes()
    expected = next(r["mappedSha256"] for r in json.loads(
        (ROOT / "reports/reference-decode-results.json").read_text())["results"]
        if r["version"] == "3.2-cn" and r["section"] == ".text")
    digest = hashlib.sha256(text).hexdigest()
    if digest != expected:
        raise ValueError("Candidate text changed")
    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(UC_CPU_ARM_926)
    cpu.mem_map(0, 0x440000)
    cpu.mem_write(0x2000, text)
    cpu.mem_map(0xc1400000, 0x200000)
    cpu.mem_map(0x20000000, 0x20000)

    def word(address):
        return struct.unpack("<I", cpu.mem_read(address, 4))[0]

    def initialize(identifier, initialized=True, flags=0):
        address = BASE + 28 * identifier
        row = bytearray(28)
        struct.pack_into("<I", row, 0, address)  # No waiting task: sentinel points to itself.
        struct.pack_into("<I", row, 8, int(initialized))
        struct.pack_into("<I", row, 0x10, flags)
        cpu.mem_write(address, bytes(row))
        return address

    def send(identifier, node, key):
        cpu.mem_write(node, struct.pack("<Ii", 0, key) + bytes(16))
        cpu.reg_write(UC_ARM_REG_CPSR, 0xd3)  # Quiescent, no scheduler/interrupt test.
        cpu.reg_write(UC_ARM_REG_SP, STACK)
        cpu.reg_write(UC_ARM_REG_LR, RETURN)
        cpu.reg_write(UC_ARM_REG_R0, identifier & 0xffffffff)
        cpu.reg_write(UC_ARM_REG_R1, node)
        cpu.emu_start(0x199874, RETURN, timeout=1_000_000, count=20_000)
        if cpu.reg_read(UC_ARM_REG_PC) != RETURN or cpu.reg_read(UC_ARM_REG_SP) != STACK:
            raise AssertionError("Queue routine did not return with its caller stack intact")
        value = cpu.reg_read(UC_ARM_REG_R0)
        return value - 0x100000000 if value & 0x80000000 else value

    results = []
    for identifier, active, flags, key, expected_status in (
            (0, True, 0, 524, -18), (151, True, 0, 524, -18),
            (-1, True, 0, 524, -18), (1, False, 0, 524, -42),
            (150, False, 0, 524, -42), (1, True, 2, 0, -17),
            (1, True, 2, -1, -17), (1, True, 2, 1, 0),
            (150, True, 2, 524, 0), (1, True, 0, 0, 0),
            (1, True, 0, -1, 0)):
        if 1 <= identifier <= 150:
            initialize(identifier, active, flags)
        status = send(identifier, NODE, key)
        if status != expected_status:
            raise AssertionError((identifier, active, flags, key, status, expected_status))
        results.append({"id": identifier, "initialized": active, "flags": flags,
                        "nodeKey": key, "return": status})
    ordering = []
    for flags, expected_indices in ((0, [0, 1, 2, 3]), (2, [1, 3, 0, 2])):
        queue = initialize(7, True, flags)
        keys = [524, 256, 1024, 256]
        for index, key in enumerate(keys):
            if send(7, NODE + index * 32, key) != 0:
                raise AssertionError("Native insertion rejected positive key")
        head = word(queue + 0x14)
        actual_indices = []
        for _ in range(len(keys) + 1):
            if head == 0:
                break
            actual_indices.append((head - NODE) // 32)
            head = word(head)
        if actual_indices != expected_indices or head != 0:
            raise AssertionError((flags, actual_indices, expected_indices))
        ordering.append({"flags": flags, "keys": keys, "order": actual_indices})
    report = {"qualification": "Candidate ARM execution with synthetic queue descriptors and no waiting tasks; not a camera trace.",
        "entry": "0x199874", "textSha256": digest, "externalCallStubs": 0,
        "validIdRangeInclusive": [1, 150], "returnCases": results, "orderingCases": ordering,
        "limits": ["No real initialization/lifetime, scheduling, concurrent tasks or camera values are observed.",
            "524 is the wrapper's fixed 0x20c input in the traced command; payload tag 0x15 is not a kernel queue ID.",
            "This does not locate a user freeze or justify dropping a failed message."]}
    (ROOT / "reports/native-message-send-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS:", len(results), "native return cases and", len(ordering), "ordering cases; no call stubs")


if __name__ == "__main__":
    main()
