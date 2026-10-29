"""Execute the original gate preceding the reused code region in both images.

This checks the constant-return branch in the file image. It cannot establish
all indirect/runtime reachability or exclude AE callbacks during startup.
"""
from pathlib import Path
import importlib.util
import json
import sys
from firmware_tokens import parse_container, layouts, parse_stream, decode, sha, require

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("incident_gate_fixture", ROOT / "scripts/check-exposure-preview-patch.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SP


def main():
    raw = (ROOT / "output/demo-packages/firmware.bin").read_bytes()
    require(sha(raw) == "6c247d53e127d0a3b3442f38b438afb15d24a7bb16fe51e6bf060fc635bc2b35", "Failed image changed")
    body = parse_container(raw)[0]["body"]
    layout = layouts(body)[".text"]
    stream = parse_stream(body[layout["start"]:layout["start"]+layout["packedSize"]])
    text = decode(stream, "sequential")[:layout["plainSize"]]
    require(text[0xf880-0x2000:0xf888-0x2000] == bytes.fromhex("0000a0e31eff2fe1"), "Original constant-return helper changed")
    rows = []
    for label, code in (("official", fx.TEXT), ("failed", text)):
        cpu, state = fx.machine(False, [(fx.SP-0x1000, fx.SP)])
        cpu.mem_write(0x2000, code)
        cpu.reg_write(UC_ARM_REG_R0, 7)
        executed = []
        cpu.hook_add(UC_HOOK_CODE, lambda c,a,s,u: executed.append(a))
        fx.execute(cpu, state, 0x369d50, 0x369e18)
        require(not any(0x369d68 <= a < 0x369dd0 for a in executed), "Original gate entered wrapper region")
        require(cpu.reg_read(UC_ARM_REG_SP) == fx.SP-0x2c0, "Unexpected enclosing function stack frame")
        rows.append(dict(image=label, visited=[hex(a) for a in executed],
            wrapperRegionEntered=False, reached=hex(cpu.reg_read(UC_ARM_REG_PC))))
    prep = json.loads((ROOT / "output/custom-shutter-demo/shutter-0062102c-48000-1ch-16bit/preparation.json").read_text(encoding="utf-8"))
    exposure = json.loads((ROOT / "reports/demo-exposure-native-validation-2026-10-29.json").read_text(encoding="utf-8"))
    report = dict(date="2026-10-29", failedSha256=sha(raw), gateExecutions=rows,
        originalHelperBytes="0000a0e31eff2fe1", originalHelperAddress="0xf880",
        enclosingFunction="0x369d50", reusedRegion=["0x369d68", "0x369dd0"],
        nativeExposureCasesPreviouslyPassed=len(exposure["cases"]),
        originalExposureFailures=exposure["failures"], audioPreparation=prep,
        rootCauseConfirmed=False, cameraAccessed=False, firmwareWritten=False,
        limits=["Reused bytes belong to a statically unreachable branch, not padding.",
            "This executes the recorded constant-return gate, not every possible entry or runtime modification.",
            "Local ABI tests do not prove that AE callbacks cannot run before the screen appears.",
            "Audio routing is based on static analysis and separate final-image checks, not speaker playback."])
    (ROOT / "reports/failed-demo-patch-gate-audit-2026-10-29.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print("PASS: original and failed images both branch over the reused region via unchanged mov r0,#0 helper; no full-startup claim.")


if __name__ == "__main__":
    main()
