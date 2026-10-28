"""Metadata prefix fixtures; no network or camera operations."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.liveview_metadata import MetadataPrefixes


def packet(frame,count,index,data):
    return struct.pack('>III',frame,count,index)+data


class PrefixTests(unittest.TestCase):
    def setUp(self):
        self.header=json.dumps({'ISOSetting':'100','ColorMode':'HContrastBW'}).encode().ljust(2048,b'\0')
        self.a=self.header[:1448];self.b=self.header[1448:]+b'JPEG-fragment'

    def test_prefix_without_complete_jpeg(self):
        p=MetadataPrefixes()
        self.assertIsNone(p.feed(packet(1,37,0,self.a),1.0))
        event=p.feed(packet(1,37,1,self.b),1.1)
        self.assertEqual(event['metadata']['ISOSetting'],'100')
        self.assertEqual(event['prefixStartedAt'],1.0)

    def test_out_of_order_prefix(self):
        p=MetadataPrefixes();p.feed(packet(2,37,1,self.b),1.0)
        self.assertEqual(p.feed(packet(2,37,0,self.a),1.1)['metadata']['ColorMode'],'HContrastBW')

    def test_duplicates_do_not_emit_twice(self):
        p=MetadataPrefixes();p.feed(packet(1,37,0,self.a))
        p.feed(packet(1,37,1,self.b))
        self.assertIsNone(p.feed(packet(1,37,1,self.b)))

    def test_missing_prefix_part_not_accepted(self):
        p=MetadataPrefixes();self.assertIsNone(p.feed(packet(1,37,1,self.b)))

    def test_two_frames_not_mixed(self):
        p=MetadataPrefixes();p.feed(packet(1,37,0,self.a))
        self.assertIsNone(p.feed(packet(2,37,1,self.b)))

    def test_inconsistent_count_rejected(self):
        p=MetadataPrefixes();p.feed(packet(1,37,0,self.a))
        self.assertIsNone(p.feed(packet(1,38,1,self.b)))

    def test_conflicting_duplicate_rejected(self):
        p=MetadataPrefixes();p.feed(packet(1,37,0,self.a))
        p.feed(packet(1,37,0,b'X'+self.a[1:]))
        self.assertIsNone(p.feed(packet(1,37,1,self.b)))

    def test_invalid_or_truncated_header_not_accepted(self):
        p=MetadataPrefixes()
        self.assertIsNone(p.feed(packet(1,1,0,b'{}')))
        self.assertIsNone(p.feed(packet(2,1,0,b'bad'.ljust(2048,b'\0'))))
        self.assertIsNone(p.feed(packet(3,1,0,b'[]'.ljust(2048,b'\0'))))

    def test_bounds_and_old_state_eviction(self):
        p=MetadataPrefixes(max_frames=2)
        for frame in range(10):p.feed(packet(frame,37,0,self.a))
        self.assertEqual(len(p.frames),2)
        self.assertIsNone(p.feed(packet(0,37,1,self.b)))
        self.assertIsNone(p.feed(packet(99,0,0,self.a)))
        self.assertIsNone(p.feed(packet(99,9999,0,self.a)))
        self.assertIsNone(p.feed(packet(99,37,37,self.a)))
        self.assertIsNone(p.feed(b'short'))


if __name__=='__main__':unittest.main()
