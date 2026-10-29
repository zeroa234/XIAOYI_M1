"""Check final-demo audio bytes and execute its original descriptor constructor."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import io
import json
import struct
import sys
import wave

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from firmware_tokens import parse_container, layouts, parse_stream, decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    args = parser.parse_args()
    body = parse_container(args.firmware.read_bytes())[0]["body"]
    sections = {}
    for name, row in layouts(body).items():
        packed = body[row["start"]:row["start"] + row["packedSize"]]
        sections[name] = decode(parse_stream(packed), "sequential")[:row["plainSize"]]
    original_ro = (ROOT / "output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin").read_bytes()
    resources = json.loads((ROOT / "output/sound-audit-2026-10-29/manifest.json").read_text(encoding="utf-8"))["files"]
    untouched = []
    for row in resources:
        address, length = int(row["va"], 0), row["declaredRIFFBytes"]
        if address == 0x62102c:
            continue
        offset = address - 0x43f800
        assert sections[".rodata"][offset:offset + length] == original_ro[offset:offset + length]
        untouched.append(hex(address))
    selected = ROOT / "output/custom-shutter-demo/shutter-0062102c-48000-1ch-16bit"
    new_resource = sections[".rodata"][0x62102c - 0x43f800:0x66777e - 0x43f800]
    with wave.open(io.BytesIO(new_resource), "rb") as w:
        assert (w.getnchannels(), w.getframerate(), w.getsampwidth()) == (1, 48000, 2)
        frames = w.readframes(w.getnframes())
        assert frames == (selected / "converted.pcm").read_bytes()
        seconds = w.getnframes() / w.getframerate()
    assert struct.unpack_from("<I", sections[".text"], 0x14ed4c - 0x2000)[0] == 0x5de4a8
    assert struct.unpack_from("<I", sections[".rodata"], 0x61ce70 - 0x43f800)[0] == 0x5de4a8
    spec = importlib.util.spec_from_file_location("sound_fixture", ROOT / "scripts/check-exposure-preview-patch.py")
    fx = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fx)
    outputs = []
    for patched in (False, True):
        cpu, state = fx.machine(False, [(fx.CFG, fx.CFG + 0x80), (fx.SP - 0x1000, fx.SP)])
        if patched:
            cpu.mem_write(0x2000, sections[".text"])
            cpu.mem_write(0x43f800, sections[".rodata"])
        cpu.reg_write(fx.UC_ARM_REG_R0, fx.CFG)
        fx.execute(cpu, state, 0x12752c)
        values = list(struct.unpack("<III", cpu.mem_read(fx.CFG, 12)))
        assert values == [0x6014d8, 0x6041e0, 0x62102c if patched else 0x610262]
        outputs.append(dict(patched=patched, pointers=[hex(v) for v in values]))
    report = dict(passed=True, firmwareSha256=hashlib.sha256(args.firmware.read_bytes()).hexdigest(),
        descriptorExecutions=outputs, untouchedOriginalWavResources=untouched,
        customSound=dict(va="0x62102c", seconds=seconds, channels=1, sampleRate=48000, bits=16,
            completeConvertedPcmMatches=True, pcmSha256=hashlib.sha256(frames).hexdigest()),
        duplicateBootAliasesPreserved=True, cameraPlaybackValidated=False,
        limits=["Source mapping is based on static capture-call analysis, not a live-camera test.",
                "Changing duplicate sound ID 1 to the retained original mono boot copy preserves its content; actual speaker behavior is untested."])
    (ROOT / "reports/integrated-demo-sound-validation-2026-10-29.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("PASS: both native descriptors, eight unchanged original WAV assets, complete selected PCM and boot aliases")


if __name__ == "__main__":
    main()
