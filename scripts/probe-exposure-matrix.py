"""有界、可恢复的取景快门/光圈/曝光补偿对照；不拍照、不录像。"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import queue
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "temp/tool-deps"))
spec = importlib.util.spec_from_file_location("m1_capture", ROOT / "scripts/capture-liveview.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
sys.path.insert(0, str(capture.UPSTREAM))
from prot_http.command_http import (RcCmdSetCameraMode, RcCmdSetFStop,
    RcCmdSetShutterSpeed, RcCmdSetExposureValueOffset)
from prot_http.const_http_cmd_rc_params import RcExposureMode, RcFStop, RcShutterSpeed, RcEvOffset

BUILDERS = {"ExposureMode": (RcCmdSetCameraMode, RcExposureMode),
            "Fnumber": (RcCmdSetFStop, RcFStop),
            "ShutterSpeed": (RcCmdSetShutterSpeed, RcShutterSpeed),
            "EV": (RcCmdSetExposureValueOffset, RcEvOffset)}


class Matrix:
    def __init__(self, destination):
        self.destination = destination
        self.result = {"说明": "原厂取景对照；不读取传感器寄存器，不代表 LCD 像素测量。",
                       "changes": [], "phases": [], "skipped": [], "restoration": {}}

    def save(self):
        (self.destination / "matrix-progress.json").write_text(
            json.dumps(self.result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def change(self, field, value, purpose):
        builder, enum = BUILDERS[field]
        payload = builder(enum(value)).to_json()
        entry = {"payload": payload, "purpose": purpose, "at": time.monotonic()-self.clock}
        self.result["changes"].append(entry)
        self.save()  # 超时也可能已生效，必须先落盘。
        try:
            entry["response"] = capture._http_payload(payload, "http://192.168.0.10")
            if not capture.successful(entry["response"]):
                raise RuntimeError("相机拒绝命令；停止测试，不重试：" + payload["command"])
        except Exception as error:
            entry["error"] = str(error)
            raise
        finally:
            self.save()
        return entry["at"]

    def phase(self, label, expected, after):
        deadline = time.monotonic()+4
        events = []
        while time.monotonic() < deadline:
            try:
                event = self.frames.get(timeout=max(0.01, deadline-time.monotonic()))
            except queue.Empty:
                break
            if event.get("prefixStartedSeconds", event["elapsedSeconds"]) < after+0.45:
                continue
            if not all(str(event["metadata"].get(k)) == str(v) for k, v in expected.items()):
                continue
            events.append(event)
            if len(events) >= 4 and events[-1]["elapsedSeconds"]-events[0]["elapsedSeconds"] >= 0.25:
                start = events[0]["elapsedSeconds"]
                end = events[-1]["elapsedSeconds"]+1.2
                while time.monotonic()-self.clock < end:
                    time.sleep(0.02)
                images = [e for e in self.session["frameEvents"] if start <= e["elapsedSeconds"] <= end
                          and all(str(e.get("metadata", {}).get(k)) == str(v) for k,v in expected.items())]
                phase = {"label": label, "expected": expected, "metadata": events,
                         "images": images, "window": [start, end]}
                self.result["phases"].append(phase)
                self.save()
                return events[-1]["metadata"]
        raise TimeoutError("新参数头未确认：" + label + " " + str(expected))

    def __call__(self, frames, session, clock_start):
        self.frames, self.session, self.clock = frames, session, clock_start
        original = None
        restore = {}
        ev_dirty = None
        try:
            original = self.phase("原设置", {"ExposureMode": "M"}, 0)
            self.result["originalMetadata"] = original
            if original.get("ISOSetting") == "Auto":
                raise RuntimeError("本对照要求原设置为固定 ISO；未改变任何设置")
            for f, (_, enum) in BUILDERS.items():
                if f != "EV":
                    enum(original[f])  # 在第一次修改前确认原值可恢复。
            for value in ("1/30s", "1/500s"):
                restore["ShutterSpeed"] = original["ShutterSpeed"]
                at = self.change("ShutterSpeed", value, "M 档快门对照")
                self.phase("M 快门 " + value, {"ExposureMode": "M", "ShutterSpeed": value,
                           "ISOSetting": original["ISOSetting"], "Fnumber": original["Fnumber"]}, at)
            at = self.change("ShutterSpeed", original["ShutterSpeed"], "恢复 M 档快门")
            self.phase("M 快门恢复", {"ExposureMode": "M", "ShutterSpeed": original["ShutterSpeed"]}, at)
            del restore["ShutterSpeed"]
            if original.get("LensStatus") != "0" and float(original.get("FnumberMax", "0")) >= 7.1:
                restore["Fnumber"] = original["Fnumber"]
                at = self.change("Fnumber", "7.1", "M 档光圈对照")
                self.phase("M 光圈 7.1", {"ExposureMode": "M", "Fnumber": "7.1"}, at)
                at = self.change("Fnumber", original["Fnumber"], "恢复 M 档光圈")
                self.phase("M 光圈恢复", {"ExposureMode": "M", "Fnumber": original["Fnumber"]}, at)
                del restore["Fnumber"]
            else:
                self.result["skipped"].append("光圈：LensStatus=0 或光圈范围不可用；不发送无法核验的光圈命令")
            restore["ExposureMode"] = "M"
            for mode in ("P", "A", "S"):
                if time.monotonic()-self.clock > 45:
                    self.result["skipped"].append(mode + "：为恢复设置保留时间，停止追加对照")
                    break
                at = self.change("ExposureMode", mode, "曝光补偿对照档位")
                before = self.phase(mode + " 原补偿", {"ExposureMode": mode}, at)
                # 非 M 档 EV 从属性 0x12 回读；M 档 EV 为单独缓存，不能拿来恢复补偿。
                saved_ev = RcEvOffset(before["EV"]).value
                target = "-2.0" if float(saved_ev) > 2 else "2.0"
                ev_dirty = (mode, saved_ev)
                at = self.change("EV", target, "非 M 档补偿对照")
                self.phase(mode + " 补偿 " + target, {"ExposureMode": mode, "EV": target}, at)
                at = self.change("EV", saved_ev, "恢复该档位原补偿")
                self.phase(mode + " 补偿恢复", {"ExposureMode": mode, "EV": saved_ev}, at)
                self.result["restoration"][mode+" EV"] = saved_ev
                ev_dirty = None
        except (Exception, KeyboardInterrupt) as error:
            self.result["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if ev_dirty:
                try:
                    mode, value = ev_dirty
                    at = self.change("EV", value, "异常清理：恢复非 M 档补偿")
                    self.phase(mode + " 异常补偿恢复", {"ExposureMode": mode, "EV": value}, at)
                    self.result["restoration"][mode+" EV"] = value
                except Exception as error:
                    self.result["restorationErrorEV"] = str(error)
            for field in ("ExposureMode", "ShutterSpeed", "Fnumber"):
                if field not in restore:
                    continue
                try:
                    at = self.change(field, restore[field], "异常/最终清理：恢复原设置")
                    self.phase(field + " 恢复确认", {field: restore[field]}, at)
                    self.result["restoration"][field] = restore[field]
                except Exception as error:
                    self.result["restorationError"+field] = str(error)
            if original:
                try:
                    self.phase("最终原设置核验", {k:original[k] for k in (
                        "ExposureMode", "ShutterSpeed", "Fnumber", "ISOSetting", "ColorMode")},
                        time.monotonic()-self.clock)
                    self.result["restoration"]["finalOriginalConfirmed"] = True
                except Exception as error:
                    self.result["restorationErrorFinal"] = str(error)
            self.save()
        return self.result


def analyze(destination, result):
    from PIL import Image, ImageStat
    phases = result["phases"]
    candidates = [e for p in phases for e in p["images"]]
    if not candidates:
        return {"结论": "没有完整 JPEG，亮度对照不可判断"}
    first = candidates[0]
    with Image.open(destination / first["file"]) as image:
        ref = image.convert("L")
    mask = ref.point(lambda v: 255 if 16 <= v <= 220 else 0)
    count = ImageStat.Stat(mask).sum[0]/255
    if not count:
        return {"结论": "基线没有可用像素，亮度对照不可判断"}
    rows = []
    for phase in phases:
        values = []
        for event in phase["images"]:
            path = destination / event["file"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == event["sha256"]
            with Image.open(path) as image:
                image.load()
                if image.size == ref.size:
                    values.append({"file": event["file"], "mean": ImageStat.Stat(image.convert("L"), mask).mean[0]})
        rows.append({"label": phase["label"], "count": len(values), "samples": values,
                     "median": statistics.median(v["mean"] for v in values) if values else None})
    return {"说明": "同一固定掩码的 8 位 JPEG 灰度均值中位数；不是线性曝光量，环境光未由人确认恒定。",
            "selectedPixelFraction": count/(ref.width*ref.height), "phases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.parse_args()
    d = ROOT / "output/live-captures" / (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+"-exposure-matrix")
    matrix = Matrix(d)
    session = capture.capture(d, seconds=55, workflow=matrix)
    # capture 的旧 limits 描述只适用于原 ISO 脚本；本次实际允许范围在上面 BUILDERS。
    session["limits"] = ["只用状态/遥控启停/档位/快门/光圈/补偿命令；不拍摄、不录像、不访问媒体或固件。",
                         "UDP 丢包与保存开销影响完整图像数；元数据不证明传感器实际施加。"]
    (d / "session.json").write_text(json.dumps(session, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    brightness = analyze(d, matrix.result)
    (d / "brightness-analysis.json").write_text(json.dumps(brightness, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    report = {"output": str(d.relative_to(ROOT)).replace("\\", "/"),
              "sessionCommands": session["commands"], "sessionError": session.get("error"),
              "stopError": session.get("stopError"), "probe": matrix.result, "brightness": brightness}
    (ROOT / "reports/exposure-matrix-results-2026-10-27.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print("采集目录：", d)
    print("恢复：", matrix.result["restoration"])
    print("错误：", matrix.result.get("error"), session.get("error"), session.get("stopError"))
    for p in brightness.get("phases", []):
        print(p["label"], p["count"], p["median"])
    return int(bool(matrix.result.get("error") or session.get("error") or session.get("stopError")
                    or any(k.startswith("restorationError") for k in matrix.result)))


if __name__ == "__main__":
    raise SystemExit(main())
