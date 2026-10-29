"""Execute the original callback tail after a synthetic semaphore return.

The peripheral register is RAM in Unicorn, not a hardware/interrupt model.
No calls are replaced; execution begins immediately after the signal call.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("error_fixture", ROOT / "scripts/check-exposure-preview-patch.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)


def case(value, channel):
    register = 0x2b000300 + channel * 0x300 + 0xe0
    cpu, status = fx.machine(False, [(register, register + 4)])
    cpu.mem_map(0x2b000000, 0x2000)
    fx.put(cpu, register, 0xffffffff)
    cpu.reg_write(fx.UC_ARM_REG_R0, value & 0xffffffff)
    cpu.reg_write(fx.UC_ARM_REG_R4, channel)
    reached = []

    def boundary(c, address, size, user):
        if address in (0x42a2f8, 0x42a2fc):
            reached.append(address)
            status["finished"] = True
            c.emu_stop()

    cpu.hook_add(fx.UC_HOOK_CODE, boundary)
    fx.execute(cpu, status, 0x42a2d4, count=30)
    good = value in (0, -43)
    assert reached == [0x42a2fc if good else 0x42a2f8]
    actual = fx.word(cpu, register)
    assert actual == (0xffffefff if good else 0xffffffff)
    assert status["writes"] == (1 if good else 0)
    return dict(signalReturn=value, channel=channel, reached=hex(reached[0]),
                modeledRegister=hex(register), modeledValue=hex(actual), writes=status["writes"])


def main():
    expected = next(r["mappedSha256"] for r in json.loads((ROOT / "reports/reference-decode-results.json").read_text())[
        "results"] if r["version"] == "3.2-cn" and r["section"] == ".text")
    assert hashlib.sha256(fx.TEXT).hexdigest() == expected
    assert struct.unpack_from("<I", fx.TEXT, 0x42a928 - 0x2000)[0] == 0x2b000300
    assert fx.TEXT[0x42a2f8 - 0x2000:0x42a2fc - 0x2000].hex() == "feffffea"
    results = [case(value, channel) for value in (0, -43, -18, -17, -42, 1, 0x7fffffff, -0x80000000) for channel in range(4)]
    report = dict(passed=True, textSha256=expected, externalCallStubs=0, cases=results,
        qualification="Original ARM tail 0x42a2d4 after synthetic signal returns; modeled registers are RAM.",
        proved="Only 0/-43 clear bit 0x1000 and continue; other tested return values reach the original branch-to-self.",
        limitations=["Does not execute the semaphore signal or its object lifecycle.",
                     "Does not establish interrupt priority/context or that the camera ever returned these errors.",
                     "A branch-to-self may be an intentional fatal invariant; returning instead is not proven safe."])
    path = ROOT / "reports/callback-error-tail-2026-10-29.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(results)} original callback-tail cases; no call stubs; no camera")


if __name__ == "__main__":
    main()
