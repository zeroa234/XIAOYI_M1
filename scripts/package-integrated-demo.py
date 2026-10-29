"""Package the reviewed demo using standard-library ZIP and SHA-256 checks."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="integrated-demo-3-2cn-v1")
    args = parser.parse_args()
    raise SystemExit("WITHDRAWN: 3.2-d1 packaging is disabled after a user-reported boot failure. Preserve the original archive as evidence; see reports/firmware-incident-2026-10-29.md.")
    import re
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.build):
        raise SystemExit("Invalid build name")
    build = ROOT / "output/firmware-builds" / args.build
    manifest_raw = (build / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    firmware = (build / "firmware.bin").read_bytes()
    assert sha(firmware) == manifest["outputSha256"]
    assert len(firmware) == manifest["outputBytes"]
    assert manifest["verification"]["passed"] is True
    assert manifest["verification"]["outputSha256"] == sha(firmware)
    for source in manifest["patchSources"]:
        assert sha((ROOT / source["path"]).read_bytes()) == source["sha256"]
    exposure_path = ROOT / "reports/demo-exposure-native-validation-2026-10-29.json"
    exposure_raw = exposure_path.read_bytes()
    exposure = json.loads(exposure_raw)
    assert len(exposure["cases"]) == 22 and not exposure["failures"]
    assert exposure["patchManifestSha256"] == sha((ROOT / "config/patches/demo-exposure-driver.json").read_bytes())
    sound_raw = (ROOT / "reports/integrated-demo-sound-validation-2026-10-29.json").read_bytes()
    sound = json.loads(sound_raw)
    assert sound["passed"] and sound["firmwareSha256"] == sha(firmware)
    assert len(sound["untouchedOriginalWavResources"]) == 8
    asset = ROOT / "output/custom-shutter-demo/shutter-0062102c-48000-1ch-16bit"
    prepared = json.loads((asset / "preparation.json").read_text(encoding="utf-8"))
    preview = (asset / "preview.wav").read_bytes()
    assert preview[:4] == b"RIFF" and preview[8:12] == b"WAVE"
    preview = preview[:struct.unpack_from("<I", preview, 4)[0] + 8]
    verification_raw = (json.dumps(manifest["verification"], indent=2) + "\n").encode()
    members = {
        "README.md": (ROOT / "docs/integrated-demo-readme.md").read_bytes(),
        "firmware.bin": firmware,
        "manifest.json": manifest_raw,
        "shutter-preview.wav": preview,
        "verification/build.json": verification_raw,
        "verification/exposure-native.json": exposure_raw,
        "verification/sound-routing.json": sound_raw,
        "verification/sound-preparation.json": (asset / "preparation.json").read_bytes(),
    }
    checksums = "".join(f"{sha(raw)}  {name}\n" for name, raw in sorted(members.items()))
    members["SHA256SUMS.txt"] = checksums.encode("utf-8")
    out = ROOT / "output/demo-packages"
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "yi-m1-3-2-d1-demo.zip"
    if archive.exists():
        raise SystemExit("Refusing to overwrite an existing delivery archive")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, raw in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, raw, compresslevel=9)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert set(z.namelist()) == set(members)
        for name, raw in members.items():
            assert z.read(name) == raw
        for line in z.read("SHA256SUMS.txt").decode().splitlines():
            expected, name = line.split("  ", 1)
            assert sha(z.read(name)) == expected
    (out / "shutter-preview.wav").write_bytes(preview)
    report = dict(
        schema=1, status="experimental-offline-demo-not-camera-validated",
        build=str(build.relative_to(ROOT)).replace("\\", "/"),
        archive=str(archive.relative_to(ROOT)).replace("\\", "/"),
        archiveBytes=archive.stat().st_size, archiveSha256=sha(archive.read_bytes()),
        firmwareBytes=len(firmware), firmwareSha256=sha(firmware),
        version="3.2-d1", cameraConnected=False, cameraTested=False,
        verification=manifest["verification"], exposureNativeCases=22,
        exposureFailures=exposure["failures"], soundVerification=sound,
        audioPreparation=prepared, archiveReadbackVerified=True,
        archiveMembers=[dict(path=n, bytes=len(b), sha256=sha(b)) for n, b in sorted(members.items())],
        nativeDecodeVerified=False,
    )
    report_path = ROOT / "reports/integrated-demo-build-2026-10-29.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("archive", "archiveBytes", "archiveSha256", "firmwareSha256", "archiveReadbackVerified")}, indent=2))


if __name__ == "__main__":
    main()
