"""Bounded direct-PC capture using the unchanged upstream M1 UDP decoder.

Own glue supplies time/size limits and raw datagram preservation. Baseline mode
uses only status/start/stop commands. An explicit probe may use ISO/color enum
setters with its own snapshot/restore workflow.
"""
import argparse
import builtins
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import socket
import sys
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.liveview_metadata import MetadataPrefixes
UPSTREAM = ROOT / "vendor/yi-m1-liveview"
DECODER = UPSTREAM / "udp_bitmap_decoder.py"
DECODER_HASH = "f527a04bb141fbaf40f3d0a4613ca692b881ca18687cfb41baaa5511f93c38de"
CAMERA = "192.168.0.10"
ALLOWED = {"GetCameraStatus", "RCStartRemoteCtl", "RCStopRemoteCtl"}


def verified_decoder():
    if hashlib.sha256(DECODER.read_bytes()).hexdigest() != DECODER_HASH:
        raise ValueError("Pinned upstream decoder changed; review it first")


def request(command, base="http://192.168.0.10"):
    if command not in ALLOWED:
        raise ValueError("Command outside capture allowlist")
    return _http_payload({"command": command}, base)


def change_setting(field, value, base="http://192.168.0.10"):
    """Only ISO/color values accepted by the existing upstream enum/builders."""
    verified_decoder()
    sys.path.insert(0, str(UPSTREAM))
    try:
        from prot_http.command_http import RcCmdSetIso, RcCmdSetColorStyle
        from prot_http.const_http_cmd_rc_params import RcIso, RcColorStyle
        if field == "ISO":
            payload = RcCmdSetIso(RcIso(value)).to_json()
        elif field == "ColorMode":
            payload = RcCmdSetColorStyle(RcColorStyle(value)).to_json()
        else:
            raise ValueError("Only ISO and color style are allowed in the exposure probe")
    finally:
        sys.path.remove(str(UPSTREAM))
    return _http_payload(payload, base)


def _http_payload(payload, base):
    query = urlencode({"data": json.dumps(payload, separators=(",", ":"))})
    # Camera traffic is local; never hand this request to a configured web proxy.
    opener = build_opener(ProxyHandler({}))
    with opener.open(base + "/?" + query, timeout=2) as response:
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("Unexpected response size")
        return {"httpStatus": response.status, "body": json.loads(body)}


def successful(result):
    return result["httpStatus"] == 200 and isinstance(result["body"], dict) and result["body"].get("code") == 200


def receive(destination, seconds, source=CAMERA, bind_address="0.0.0.0", drain_until_stop=False,
            on_frame=None, grace_seconds=6, on_metadata=None):
    verified_decoder()
    real_socket = socket.socket
    started = time.monotonic()
    records = []
    byte_count = 0
    ignored = 0
    drained = 0
    packets = []
    receive_buffer = None
    reason = "time-limit"
    prefixes = MetadataPrefixes()
    with zipfile.ZipFile(destination / "datagrams.zip", "x", compression=zipfile.ZIP_STORED) as archive:
        class LimitedSocket:
            def __init__(self, *args, **kwargs):
                nonlocal receive_buffer
                self.inner = real_socket(*args, **kwargs)
                self.inner.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
                receive_buffer = self.inner.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.inner.close()
            def bind(self, address):
                self.inner.bind((bind_address, address[1]))
                (destination / "receiver-ready").touch()
            def settimeout(self, value):
                self.inner.settimeout(min(value, 0.2))
            def recvfrom(self, size):
                nonlocal byte_count, ignored, reason, drained
                while True:
                    if (destination / "receiver-stop").exists():
                        reason = "requested-stop"
                        raise KeyboardInterrupt
                    elapsed = time.monotonic()-started
                    limited = elapsed >= seconds or byte_count >= 32*1024*1024 or len(records) >= 32768
                    if limited and (not drain_until_stop or elapsed >= seconds+grace_seconds):
                        raise KeyboardInterrupt
                    packet, peer = self.inner.recvfrom(size)
                    if peer[0] != source:
                        ignored += 1
                        continue
                    if limited:
                        drained += 1
                        continue
                    name = f"{len(records):06d}.udp"
                    packets.append(packet)
                    records.append({"file": name, "elapsedSeconds": time.monotonic()-started,
                                    "sourcePort": peer[1], "bytes": len(packet)})
                    byte_count += len(packet)
                    if on_metadata:
                        event = prefixes.feed(packet,time.monotonic())
                        if event is not None:
                            on_metadata(event)
                    return packet, peer
        # Dependency injection stays local to the upstream script's namespace.
        # Its decoder logic/file stays unchanged; HTTP sockets are unaffected.
        scoped = dict(vars(builtins))
        def decoder_import(name, *args, **kwargs):
            if name == "socket":
                return SimpleNamespace(socket=LimitedSocket, AF_INET=socket.AF_INET,
                                       SOCK_DGRAM=socket.SOCK_DGRAM)
            return builtins.__import__(name, *args, **kwargs)
        def decoder_open(name, *args, **kwargs):
            path = Path(name)
            if path.is_absolute() or path.parent != Path("."):
                raise ValueError("Unexpected upstream output path")
            handle = builtins.open(destination/path, *args, **kwargs)
            if on_frame is None or path.suffix != ".jpg":
                return handle
            class CompletedFrame:
                def __enter__(self):
                    return handle.__enter__()
                def __exit__(self, kind, value, traceback):
                    answer = handle.__exit__(kind, value, traceback)
                    if kind is None:
                        on_frame(destination/path)
                    return answer
            return CompletedFrame()
        with (destination/"receiver.log").open("w", encoding="utf-8") as console:
            scoped.update(__import__=decoder_import, open=decoder_open,
                          print=lambda *args, **kwargs: builtins.print(*args, file=console, flush=True))
            namespace = {"__name__":"__main__", "__file__":str(DECODER), "__builtins__":scoped}
            sys.path.insert(0, str(UPSTREAM))
            try:
                exec(compile(DECODER.read_bytes(), str(DECODER), "exec"), namespace)
            finally:
                sys.path.remove(str(UPSTREAM))
        for record, packet in zip(records, packets):
            archive.writestr(record["file"], packet)
        archive.writestr("manifest.json", json.dumps({"qualification": "UDP application datagrams, not a wire-level PCAP or CPU trace.",
            "reason": reason, "bytes": byte_count, "ignoredOtherSources": ignored,
            "drainedAfterLimit": drained, "receiveBufferBytes": receive_buffer, "records": records}, indent=2))
    return {"datagrams": len(records), "bytes": byte_count, "reason": reason}


def capture(destination, seconds=10, base="http://192.168.0.10", source=CAMERA, bind_address="0.0.0.0",
            workflow=None):
    verified_decoder()
    destination.mkdir(parents=True, exist_ok=False)
    result = {"startedUtc": datetime.now(timezone.utc).isoformat(), "requestedSeconds": seconds,
              "commands": [], "qualification": "Observer-side direct-PC baseline; not a firmware repair or local-menu timing test."}
    stop_needed = False
    receiver_errors = []
    frames = queue.Queue()
    clock_start = time.monotonic()
    receiver_seconds = seconds+10 if workflow else seconds
    result["receiverRecordLimitSeconds"] = receiver_seconds
    result["frameEvents"] = []
    result["metadataEvents"] = []
    def completed_metadata(event):
        event["elapsedSeconds"] = time.monotonic()-clock_start
        if event.get("prefixStartedAt") is not None:
            event["prefixStartedSeconds"] = event.pop("prefixStartedAt")-clock_start
        result["metadataEvents"].append(event)
        if workflow is not None:
            frames.put(event)
    def completed_frame(path):
        event = {"kind":"image","file": path.name, "elapsedSeconds": time.monotonic()-clock_start,
                 "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
        try:
            header = path.with_suffix(".txt").read_bytes().split(b"\0", 1)[0].decode("utf-8").strip()
            event["metadata"] = json.loads(header)
        except (ValueError, OSError) as error:
            event["metadataError"] = str(error)
        result["frameEvents"].append(event)
        if workflow is None:
            frames.put(event)
    def run_receiver():
        try:
            receive(destination, receiver_seconds, source, bind_address, drain_until_stop=True,
                    on_frame=completed_frame, grace_seconds=4 if workflow else 6,on_metadata=completed_metadata)
        except Exception as error:
            receiver_errors.append(type(error).__name__ + ": " + str(error))
    receiver = threading.Thread(target=run_receiver, daemon=True)
    receiver.start()
    try:
        ready_deadline = time.monotonic()+4
        while not (destination / "receiver-ready").exists():
            if not receiver.is_alive() or time.monotonic() >= ready_deadline:
                raise RuntimeError("Receiver did not become ready; inspect receiver.log")
            time.sleep(0.05)
        status = request("GetCameraStatus", base)
        result["commands"].append({"command": "GetCameraStatus", **status})
        if not successful(status):
            raise RuntimeError("Camera status response was not recognized as successful")
        stop_needed = True  # A lost start reply can still leave our stream active.
        started = request("RCStartRemoteCtl", base)
        result["commands"].append({"command": "RCStartRemoteCtl", **started})
        if not successful(started):
            body = started.get("body")
            # An explicit camera error belongs to no session we successfully started.
            # Keep cleanup for an ambiguous/malformed success reply.
            stop_needed = not (isinstance(body, dict) and isinstance(body.get("code"), int)
                               and body["code"] not in (0, 200))
            raise RuntimeError("Camera rejected remote start; no retry performed")
        if workflow is not None:
            result["workflow"] = workflow(frames, result, clock_start)
        else:
            deadline = time.monotonic()+seconds
            while time.monotonic() < deadline:
                if not receiver.is_alive() or receiver_errors:
                    raise RuntimeError("Receiver stopped early: " + str(receiver_errors))
                time.sleep(0.05)
        result["captureWindowFinished"] = True
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = type(error).__name__ + ": " + str(error)
    finally:
        # Send stop while the UDP socket is still draining. Close only afterwards.
        if stop_needed:
            try:
                result["commands"].append({"command": "RCStopRemoteCtl", **request("RCStopRemoteCtl", base)})
            except Exception as error:
                result["stopError"] = str(error)
        (destination / "receiver-stop").touch()
        receiver.join(timeout=3)
        if receiver.is_alive():
            result["receiverStillRunning"] = True
        else:
            result["receiverCompleted"] = True
        if receiver_errors:
            result["receiverErrors"] = receiver_errors
        result["orderedFramesSaved"] = len(list(destination.glob("packet_*.jpg")))
        result["limits"] = ["Upstream decoder accepts only fully ordered frames; out-of-order or lost frames may be omitted.",
            "Raw datagrams are preserved for a better existing assembler; missing saved JPEGs do not prove camera hangs.",
            "Host scheduling, Wi-Fi and recording overhead affect observed timing.",
            "No aperture/shutter changes, shutter release, video recording, file deletion or firmware command."]
        if workflow is None:
            result["limits"].append("Baseline mode makes no ISO or color style changes.")
        (destination / "session.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="One status request only")
    modes.add_argument("--capture", action="store_true", help="Start, capture briefly, then stop remote view")
    parser.add_argument("--seconds", type=int, default=10, choices=range(1, 16), metavar="1..15")
    args = parser.parse_args()
    if args.check:
        response = request("GetCameraStatus")
        print(json.dumps(response, ensure_ascii=False))
    else:
        name = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        destination = ROOT / "output/live-captures" / name
        result = capture(destination, args.seconds)
        print("Saved:", destination)
        print("Ordered frames saved:", result["orderedFramesSaved"])
        if "error" in result:
            print("Capture incomplete:", result["error"])
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
