"""One bounded ISO/color preview comparison with original-setting restoration.

Reuses the pinned upstream control enum/builders and existing capture tool.
HTTP success and stream metadata are checked separately; neither proves sensor
registers or final photo exposure. No shutter release or recording is performed.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
from pathlib import Path
import queue
import statistics
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("m1_capture", ROOT/"scripts/capture-liveview.py")
capture_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture_tool)
FIXED_ISOS = ("100","200","400","800","1600","3200","6400","12800","25600")
COLORS = {"Standard","Portrait","Vivid","NaturalBW","HContrastBW"}


class Probe:
    def __init__(self, destination, base="http://192.168.0.10", timeout=2.0,
                 settle=0.35, min_frames=2, min_span=0.15, image_window=1.0,require_baseline_image=True):
        self.destination = destination
        self.base = base
        self.timeout = timeout
        self.settle = settle
        self.min_frames = min_frames
        self.min_span = min_span
        self.image_window = image_window
        self.require_baseline_image = require_baseline_image
        self.result = {"qualification":"Setting/preview observation only, not a firmware fix.",
                       "changes":[],"phases":[],"restoration":{}}

    def save(self):
        (self.destination/"probe-progress.json").write_text(json.dumps(self.result,indent=2)+"\n")

    def change(self, field, value, purpose):
        entry = {"field":field,"value":value,"purpose":purpose,
                 "elapsedSeconds":time.monotonic()-self.clock}
        self.result["changes"].append(entry)
        self.save()  # Record intent before sending: a timeout may still apply the value.
        try:
            entry["response"] = capture_tool.change_setting(field,value,self.base)
            entry["replyElapsedSeconds"] = time.monotonic()-self.clock
            if not capture_tool.successful(entry["response"]):
                raise RuntimeError("Camera rejected " + field)
        except Exception as error:
            entry["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            self.save()
        return entry["elapsedSeconds"]

    def collect(self, expected, after, label=None, initial=False,required_count=None):
        deadline = time.monotonic()+self.timeout
        records = []
        while time.monotonic() < deadline:
            try:
                event = self.frames.get(timeout=max(0.01,deadline-time.monotonic()))
            except queue.Empty:
                break
            metadata = event.get("metadata",{})
            if event.get("prefixStartedSeconds",event["elapsedSeconds"]) < after+self.settle:
                continue
            if not all(str(metadata.get(key)) == value for key,value in expected.items()):
                continue
            if not initial:
                for key in ("ExposureMode","Fnumber","ShutterSpeed"):
                    if str(metadata.get(key)) != self.original[key]:
                        raise RuntimeError("A non-test parameter changed: " + key)
            records.append(event)
            needed=self.min_frames if required_count is None else required_count
            if len(records) >= needed and (needed==1 or records[-1]["elapsedSeconds"]-records[0]["elapsedSeconds"] >= self.min_span):
                if label:
                    self.result["phases"].append({"label":label,"expected":expected,"frames":records})
                    self.save()
                return records
        raise TimeoutError("Fresh stream metadata not confirmed for " + str(expected))

    def __call__(self, frames, session, clock_start):
        self.frames = frames
        self.clock = clock_start
        self.session = session
        iso_dirty = False
        color_dirty = False
        try:
            first = self.collect({"ExposureMode":"M"},after=0,initial=True)[-1]["metadata"]
            self.original = {key:str(first.get(key)) for key in
                ("ExposureMode","ISOSetting","ColorMode","Fnumber","ShutterSpeed")}
            if self.original["ISOSetting"] not in FIXED_ISOS[:-1] or self.original["ColorMode"] not in COLORS:
                raise ValueError("Probe requires a known fixed ISO below 25600 and a known color style")
            if any(self.original[key] in ("", "None") for key in ("Fnumber","ShutterSpeed")):
                raise ValueError("Shutter and aperture metadata must be available")
            target = FIXED_ISOS[FIXED_ISOS.index(self.original["ISOSetting"])+1]
            self.result.update(original=self.original,targetISO=target)
            self.result["restoration"].update(ISO="unchanged",ColorMode="unchanged")
            self.save()
            expected = {"ColorMode":"Standard","ISOSetting":self.original["ISOSetting"]}
            after = time.monotonic()-self.clock
            if self.original["ColorMode"] != "Standard":
                color_dirty = True
                after = self.change("ColorMode","Standard","temporary-neutral-style")
            baseline=self.observe_phase(expected,after,"baseline-standard")
            if self.require_baseline_image and not baseline["images"]:
                raise RuntimeError("No complete neutral baseline image; ISO was not changed")
            iso_dirty = True
            after = self.change("ISO",target,"one-stop-comparison")
            self.observe_phase({"ColorMode":"Standard","ISOSetting":target},after,"higher-iso")
        except (Exception,KeyboardInterrupt) as error:
            self.result["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if iso_dirty:
                try:
                    after = self.change("ISO",self.original["ISOSetting"],"restore-original-iso")
                    self.observe_phase({"ISOSetting":self.original["ISOSetting"],"ColorMode":"Standard"},
                                       after,"restored-iso-standard",required_count=1)
                    self.result["restoration"]["ISO"] = "metadata-confirmed"
                except (Exception,KeyboardInterrupt) as error:
                    self.result["restoration"]["ISO"] = "not-confirmed: " + str(error)
            if color_dirty:
                try:
                    after = self.change("ColorMode",self.original["ColorMode"],"restore-original-style")
                    self.collect({"ColorMode":self.original["ColorMode"]},after,required_count=1)
                    self.result["restoration"]["ColorMode"] = "metadata-confirmed"
                except (Exception,KeyboardInterrupt) as error:
                    self.result["restoration"]["ColorMode"] = "not-confirmed: " + str(error)
            self.result["restorationIncomplete"] = any(str(value).startswith("not-confirmed")
                for value in self.result["restoration"].values())
            self.save()
        return self.result

    def observe_phase(self,expected,after,label,required_count=None):
        self.collect(expected,after,label,required_count=required_count)
        phase=self.result["phases"][-1]
        # Keep a short stable window for JPEG evidence, separate from state confirmation.
        time.sleep(self.image_window)
        phase["imageStart"]=phase["frames"][0]["elapsedSeconds"]
        phase["imageEnd"]=time.monotonic()-self.clock
        phase["images"]=[event for event in self.session.get("frameEvents",[])
            if phase["imageStart"]<=event["elapsedSeconds"]<=phase["imageEnd"]
            and all(str(event.get("metadata",{}).get(k))==v for k,v in expected.items())
            and all(str(event.get("metadata",{}).get(k))==self.original[k]
                    for k in ("ExposureMode","Fnumber","ShutterSpeed"))]
        self.save()
        return phase


def analyze(destination, probe):
    from PIL import Image, ImageStat
    phases = probe.get("phases",[])
    baseline = next((p for p in phases if p["label"] == "baseline-standard"),None)
    if not baseline:
        return {"inconclusive":"No verified neutral-style baseline"}
    baseline_images=baseline.get("images",baseline["frames"])
    baseline_images=[event for event in baseline_images if event.get("file")]
    if not baseline_images:
        return {"inconclusive":"Neutral-style metadata confirmed, but no complete baseline JPEG"}
    reference_event=baseline_images[-1]
    reference = destination/reference_event["file"]
    if reference_event.get("sha256") and hashlib.sha256(reference.read_bytes()).hexdigest()!=reference_event["sha256"]:
        return {"inconclusive":"Baseline file was overwritten; original frame evidence not available"}
    with Image.open(reference) as im:
        image = im.convert("L")
    mask = image.point(lambda value:255 if 16 <= value <= 220 else 0)
    selected = ImageStat.Stat(mask).sum[0]/255
    if selected == 0:
        return {"inconclusive":"Baseline has no selected nonsaturated pixels"}
    result = {"metric":"Mean JPEG luma over the SAME baseline pixels whose values are 16..220; not linear sensor exposure.",
              "selectedPixelFraction":selected/(image.width*image.height),"phases":[]}
    for phase in phases:
        samples = []
        for event in phase.get("images",phase["frames"]):
            if not event.get("file"):
                continue
            try:
                if event.get("sha256") and hashlib.sha256((destination/event["file"]).read_bytes()).hexdigest()!=event["sha256"]:
                    continue
                with Image.open(destination/event["file"]) as im:
                    im.load()
                    luma = im.convert("L")
                if luma.size != image.size:
                    continue
                samples.append({"file":event["file"],"meanLuma":ImageStat.Stat(luma,mask).mean[0]})
            except (OSError,ValueError):
                continue
        result["phases"].append({"label":phase["label"],"samples":samples,
            "medianMeanLuma":statistics.median(x["meanLuma"] for x in samples) if samples else None})
    result["limits"] = ["Lighting, scene motion, continuous focus, auto WB and JPEG tone response can affect this metric.",
        "No automatic pass/fail threshold, sensor ISO inference or performance conclusion is made.",
        "Metadata confirmation proves the reported settings, not actual sensor register application."]
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true",required=True,
                        help="Explicitly run one ISO/color comparison and restore original settings")
    parser.parse_args()
    name = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+"-iso-probe-"+uuid.uuid4().hex[:6]
    destination = ROOT/"output/live-captures"/name
    probe = Probe(destination)
    session = capture_tool.capture(destination,seconds=15,workflow=probe)
    analysis = analyze(destination,probe.result)
    (destination/"brightness-analysis.json").write_text(json.dumps(analysis,indent=2)+"\n")
    print("Saved:",destination)
    print("Original:",probe.result.get("original"))
    print("Restoration:",probe.result["restoration"])
    if "error" in session or "error" in probe.result or probe.result.get("restorationIncomplete") or session.get("stopError"):
        print("Probe incomplete:",session.get("error"),probe.result.get("error"))
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
