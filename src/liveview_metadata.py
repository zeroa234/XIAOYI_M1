"""Bounded extraction of the published M1 2048-byte metadata prefix.

The existing upstream JPEG assembler remains unchanged. This small adapter only
reassembles contiguous prefix fragments of the same frame; missing image bytes
are never fabricated or used as an image. Format source: pinned bullbin decoder.
"""
from collections import OrderedDict
import json
import struct


class MetadataPrefixes:
    def __init__(self, max_frames=8, max_prefix_parts=64):
        self.frames = OrderedDict()
        self.max_frames = max_frames
        self.max_prefix_parts = max_prefix_parts

    def feed(self, packet, observed_at=None):
        if len(packet) <= 12:
            return None
        frame, count, index = struct.unpack_from(">III",packet)
        if not 1 <= count <= 4096 or index >= count or index >= self.max_prefix_parts:
            return None
        state = self.frames.get(frame)
        if state is None:
            state = {"count":count,"parts":{},"done":False,"invalid":False,"firstObserved":observed_at}
            self.frames[frame] = state
        self.frames.move_to_end(frame)
        while len(self.frames) > self.max_frames:
            self.frames.popitem(last=False)
        if state["done"] or state["invalid"]:
            return None
        if state["count"] != count:
            state["invalid"] = True
            return None
        fragment = packet[12:12+2048]
        old = state["parts"].get(index)
        if old is not None and old != fragment:
            state["invalid"] = True
            return None
        state["parts"][index] = fragment
        prefix = bytearray()
        part = 0
        while part in state["parts"] and len(prefix) < 2048:
            prefix.extend(state["parts"][part])
            part += 1
        if len(prefix) < 2048:
            return None
        state["done"] = True
        state["parts"].clear()
        try:
            metadata = json.loads(bytes(prefix[:2048]).split(b"\0",1)[0].decode("utf-8").strip())
        except (ValueError,UnicodeDecodeError):
            return None
        if not isinstance(metadata,dict):
            return None
        return {"kind":"metadata","frameIndex":frame,"metadata":metadata,
                "prefixStartedAt":state["firstObserved"],
                "evidence":"complete-2048-byte-prefix; JPEG completeness not asserted"}
