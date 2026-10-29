"""Use FFmpeg to fit the user's selected sound into one existing PCM WAV slot.

Preserves the complete decoded clip and pads silence; no truncation or speed
change. A chosen rate/bit depth is experimental until the camera plays it.
The caller must supply an instruction-reviewed shutter resource address.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import shutil
import struct
import subprocess
import wave

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "c65e5b132a1d11567ce2237da36a0a58fa320cc592d7605914e315aa020db772"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--va", required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--bits", type=int, choices=(8, 16), required=True)
    parser.add_argument("--channels", type=int, choices=(1, 2), default=1)
    parser.add_argument("--external-padding", action="store_true", help="Write a complete short WAV and pad the unused slot outside RIFF")
    args = parser.parse_args()
    source = ROOT / "data/input/custom-sounds/shutter-selected.mp3"
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA:
        raise ValueError("Selected user sound changed")
    metadata = json.loads((ROOT / "output/sound-audit-2026-10-29/manifest.json").read_text(encoding="utf-8"))
    va = int(args.va, 0)
    row = next(r for r in metadata["files"] if int(r["va"], 0) == va)
    ro = (ROOT / "output/reference-decoded/body-3-2-cn/rodata.mapped.candidate.bin").read_bytes()
    original = ro[va - 0x43f800:va - 0x43f800 + row["declaredRIFFBytes"]]
    if hashlib.sha256(original).hexdigest() != row["sha256"] or not row["waveValid"]:
        raise ValueError("Original WAV source/hash changed")
    fmt = next(r for r in row["chunks"] if r["id"] == "fmt ")
    data = next(r for r in row["chunks"] if r["id"] == "data")
    if fmt["formatTag"] != 1 or fmt["size"] != 16:
        raise ValueError("Only the verified 16-byte PCM fmt chunk is supported")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise ValueError("Existing FFmpeg is required")
    name = f"shutter-{va:08x}-{args.rate}-{args.channels}ch-{args.bits}bit"
    out = ROOT / "output/custom-shutter-demo" / name
    if out.exists():
        raise ValueError("Refusing to overwrite prepared sound")
    out.mkdir(parents=True)
    codec, raw_format = ("pcm_u8", "u8") if args.bits == 8 else ("pcm_s16le", "s16le")
    raw_path = out / "converted.pcm"
    command = [ffmpeg, "-hide_banner", "-loglevel", "error", "-i", str(source), "-map_metadata", "-1",
               "-ac", str(args.channels), "-ar", str(args.rate), "-c:a", codec, "-f", raw_format, str(raw_path)]
    subprocess.run(command, check=True, cwd=ROOT)
    pcm = raw_path.read_bytes()
    if len(pcm) > data["size"]:
        raise ValueError(f"Full clip does not fit: {len(pcm)} > {data['size']}; no trimming performed")
    block = args.channels * args.bits // 8
    if len(pcm) % block or data["size"] % block:
        raise ValueError("PCM frame alignment mismatch")
    external_padding = 0
    if args.external_padding:
        buffer = io.BytesIO()
        with wave.open(buffer, "wb") as w:
            w.setnchannels(args.channels)
            w.setsampwidth(args.bits // 8)
            w.setframerate(args.rate)
            w.writeframes(pcm)
        complete_wav = buffer.getvalue()
        if len(complete_wav) > len(original):
            raise ValueError("Full WAV does not fit original asset slot")
        external_padding = len(original) - len(complete_wav)
        modified = bytearray(complete_wav + b"\x00" * external_padding)
    else:
        modified = bytearray(original)
        fmt_offset, data_offset = fmt["bodyVa"] - va, data["bodyVa"] - va
        struct.pack_into("<HHIIHH", modified, fmt_offset, 1, args.channels, args.rate, args.rate * block, block, args.bits)
        silence = b"\x80" if args.bits == 8 else b"\x00"
        modified[data_offset:data_offset + data["size"]] = pcm + silence * (data["size"] - len(pcm))
    with wave.open(io.BytesIO(modified), "rb") as w:
        assert w.getnchannels() == args.channels and w.getframerate() == args.rate and w.getsampwidth() == args.bits // 8
        frames = w.readframes(w.getnframes())
        assert frames[:len(pcm)] == pcm and len(frames) == (len(pcm) if args.external_padding else data["size"])
    (out / "preview.wav").write_bytes(modified)
    patch = dict(schema_version=1, id=name, status="experimental-shutter-sound-only",
        patches=[dict(section=".rodata", va=hex(va), orig_hex=original.hex(), new_hex=bytes(modified).hex(),
                      note="Replace this reviewed speaker shutter WAV only; complete selected clip, FFmpeg conversion and silence padding.")])
    (out / "patches.json").write_text(json.dumps(patch, indent=2) + "\n", encoding="utf-8")
    report = dict(sourceSha256=SOURCE_SHA, originalResourceVa=hex(va), originalSha256=row["sha256"],
        outputSha256=hashlib.sha256(modified).hexdigest(), resourceBytes=len(modified), pcmClipBytes=len(pcm),
        sampleRate=args.rate, bits=args.bits, channels=args.channels, clipSeconds=len(pcm) / (args.rate * block),
        paddedSeconds=len(frames) / (args.rate * block), paddingOutsideRIFFBytes=external_padding,
        truncated=False, speedChanged=False,
        cameraPlaybackValidated=False, command=command,
        ffmpegVersion=subprocess.run([ffmpeg, "-version"], capture_output=True, text=True, check=True).stdout.splitlines()[0])
    (out / "preparation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(output=out.relative_to(ROOT).as_posix(), **{k: report[k] for k in ("resourceBytes", "pcmClipBytes", "clipSeconds", "paddedSeconds")}), indent=2))


if __name__ == "__main__":
    main()
