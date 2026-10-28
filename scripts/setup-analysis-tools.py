"""Download official portable analysis tools into this project and verify hashes."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(item):
    kind, record = item
    downloads = ROOT / "temp/downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / record["name"]
    expected = record.get("sha256") or record["sha256FromReleasePage"]
    if archive.exists():
        if archive.stat().st_size != record["bytes"] or file_hash(archive) != expected:
            raise ValueError(f"Existing archive failed verification: {kind}")
    else:
        temporary = archive.with_suffix(archive.suffix + ".partial")
        request = urllib.request.Request(record["url"], headers={"User-Agent": "yi-m1-firmware-research"})
        digest = hashlib.sha256()
        count = 0
        next_progress = 32 * 1024 * 1024
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as stream:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                stream.write(chunk)
                digest.update(chunk)
                count += len(chunk)
                if count >= next_progress:
                    print(f"{kind}: downloaded {count // 1048576} MiB", flush=True)
                    next_progress += 32 * 1024 * 1024
        if count != record["bytes"] or digest.hexdigest() != expected:
            raise ValueError(f"Downloaded archive failed verification: {kind}")
        temporary.replace(archive)
    destination = ROOT / "vendor" / ("ghidra" if kind == "ghidra" else "java25")
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / ".verified-source.json"
    if marker.exists():
        if json.loads(marker.read_text())["sha256"] != expected:
            raise ValueError("Existing installation differs; refusing overlay")
    else:
        if any(destination.iterdir()):
            raise ValueError("Refusing to extract on top of a partial installation")
        with zipfile.ZipFile(archive) as package:
            for entry in package.infolist():
                if not (destination / entry.filename).resolve().is_relative_to(destination.resolve()):
                    raise ValueError("Archive member escapes the project installation directory")
            package.extractall(destination)
        marker.write_text(json.dumps({"url": record["url"], "sha256": expected}, indent=2) + "\n")
    directories = [p for p in destination.iterdir() if p.is_dir()]
    if len(directories) != 1:
        raise ValueError(f"Unexpected installation roots for {kind}")
    print(f"{kind}: verified and extracted", flush=True)
    return {"kind": kind, "directory": str(directories[0]), "archive": str(archive.relative_to(ROOT)), "sha256": expected}


def main():
    metadata = json.loads((ROOT / "reports/toolchain-sources.json").read_text())
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(prepare, [(kind, metadata[kind]) for kind in ("ghidra", "java")]))
    (ROOT / "reports/toolchain-installed.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
