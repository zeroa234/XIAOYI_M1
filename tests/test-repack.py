"""token 保留构建的边界与拒绝用例；不访问设备。"""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from firmware_tokens import (START, Token, Stream, parse_stream, serialize_stream, decode,
    splice, literal_tokens, official_bytes, parse_container, layouts)
from repack import build_firmware, section_changes, normalize_patches

spec = importlib.util.spec_from_file_location("verify_build", ROOT / "scripts/verify-build.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def fixture(items):
    tokens, pos = [], 0
    for item in items:
        if isinstance(item, bytes):
            for value in item:
                tokens.append(Token(True, bytes([value]), pos, 1))
                pos += 1
        else:
            source, length = item
            index = (START + source) & 4095
            tokens.append(Token(False, bytes([index & 255, ((index >> 8) << 4) | (length - 3)]), pos, length))
            pos += length
    return parse_stream(serialize_stream(Stream(tokens, 0, b"", pos)))


class TokenTests(unittest.TestCase):
    def check_change(self, stream, positions):
        seq, snap = decode(stream, "sequential"), decode(stream, "snapshot")
        changes = {p: (seq[p], value) for p, value in positions.items()}
        new, stats = splice(stream, seq, snap, changes)
        encoded = serialize_stream(new)
        parsed = parse_stream(encoded)
        for semantics, original in (("sequential", seq), ("snapshot", snap)):
            expected = bytearray(original)
            for p, (_, value) in changes.items():
                expected[p] = value
            self.assertEqual(decode(parsed, semantics), expected)
        verify.provenance(stream, parsed, seq, snap, changes)
        return parsed, stats

    def test_partial_flag_unused_bits(self):
        for packed in (b"\xffABC", b"\x81Z", b"\x00\xee\xf0", b"\xffABCDEFGH\x80", b""):
            self.assertEqual(serialize_stream(parse_stream(packed)), packed)

    def test_truncated_reference_rejected(self):
        with self.assertRaisesRegex(ValueError, "截断"):
            parse_stream(b"\x00A")

    def test_patch_inside_match(self):
        new, stats = self.check_change(fixture([b"ABCDEFGH", (0, 8)]), {11: ord("x")})
        self.assertEqual(stats["newLiterals"], 8)

    def test_patch_across_flag_groups(self):
        self.check_change(fixture([b"ABCDEFGHIJK"]), {7: ord("x"), 8: ord("y")})

    def test_patch_at_stream_end(self):
        self.check_change(fixture([b"ABCDEFGHI"]), {8: ord("x")})

    def test_patch_crosses_section_end_rejected(self):
        patches = normalize_patches([dict(section=".data", va="0x1008", orig_hex="4142", new_hex="4344", note="边界")])
        with self.assertRaisesRegex(ValueError, "段边界"):
            section_changes(patches, ".data", dict(va=0x1000, plainSize=9), b"A" * 9)

    def test_wrong_original_rejected(self):
        stream = fixture([b"ABCD"])
        with self.assertRaisesRegex(ValueError, "原字节"):
            splice(stream, b"ABCD", b"ABCD", {1: (ord("Z"), ord("x"))})

    def test_later_references_literalized(self):
        new, stats = self.check_change(fixture([b"ABCDEFGH", (0, 8), (0, 8)]), {2: ord("x")})
        self.assertEqual(stats["dependentTokens"], 2)
        self.assertTrue(all(t.literal for t in new.tokens))

    def test_patch_outside_mask_rejected(self):
        stream = fixture([b"ABCD", (2, 6)])
        seq, snap = decode(stream, "sequential"), decode(stream, "snapshot")
        self.assertNotEqual(seq[6], snap[6])
        with self.assertRaisesRegex(ValueError, "语义无关掩码"):
            splice(stream, seq, snap, {6: (seq[6], ord("x"))})

    def test_whole_match_must_be_in_mask(self):
        stream = fixture([b"ABCD", (2, 6)])
        seq, snap = decode(stream, "sequential"), decode(stream, "snapshot")
        self.assertEqual(seq[4], snap[4])
        with self.assertRaisesRegex(ValueError, "整个 token"):
            splice(stream, seq, snap, {4: (seq[4], ord("x"))})

    def test_dependent_ambiguous_match_rejected(self):
        stream = fixture([b"ABCD", (2, 6)])
        with self.assertRaisesRegex(ValueError, "整个 token"):
            splice(stream, decode(stream, "sequential"), decode(stream, "snapshot"), {2: (ord("C"), ord("x"))})

    def test_window_wrap_and_expired_dirty_slot(self):
        stream = fixture([bytes(4096 + 18), (4096, 18)])
        new, stats = self.check_change(stream, {2: 1})
        self.assertEqual(stats["dependentTokens"], 0)
        self.assertFalse(new.tokens[-1].literal)

    def test_long_zero_run_max_official_match(self):
        stream = fixture([bytes(18), (0, 18), (0, 18)])
        self.check_change(stream, {20: 1})

    def test_new_match_rejected_by_provenance(self):
        old = fixture([b"ABCDEFGH", (0, 8)])
        new = fixture([b"ABCDEFGH", (1, 8)])
        with self.assertRaisesRegex(ValueError, "官方 token"):
            verify.provenance(old, new, decode(old, "sequential"), decode(old, "snapshot"), {})

    def test_changed_unused_flag_bits_rejected(self):
        old, new = parse_stream(b"\x03AB"), parse_stream(b"\x83AB")
        with self.assertRaisesRegex(ValueError, "未使用位"):
            verify.provenance(old, new, b"AB", b"AB", {})

    def test_no_patch_preserves_synthetic_stream(self):
        old = fixture([b"ABCDEFGH", (0, 8)])
        result, stats = splice(old, decode(old, "sequential"), decode(old, "snapshot"), {})
        self.assertEqual(serialize_stream(old), serialize_stream(result))


class OfficialTests(unittest.TestCase):
    def test_zero_patch_build_is_official_byte_for_byte(self):
        original = official_bytes()
        result, rows = build_firmware(original, [])
        self.assertEqual(result, original)
        self.assertEqual([r["growth"] for r in rows], [0, 0, 0])
        self.assertTrue(all(r["serializationIdentical"] for r in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
