"""Tests for bin/ue-locres and bin/ue-save against files built here.

The layouts follow what CUE4Parse reads: locres versions 0 to 2, and GVAS
saves with and without the custom version block, the property GUID byte and
the inner tag of struct arrays. Run with `python3 -m unittest discover -s tests`.
"""
import datetime
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
LOCRES_MAGIC = struct.pack("<4I", 0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3)
ENTRIES = [("", "door_title", "Old Door"), ("", "door_hint", "Push\tthe door\nslowly"), ("UI", "greeting", "Olá")]


def fstring(text):
    """An FString, UTF-16 when the text isn't plain ASCII, as Unreal writes it."""
    if not text:
        return struct.pack("<i", 0)
    if text.isascii():
        raw = text.encode() + b"\0"
        return struct.pack("<i", len(raw)) + raw
    raw = text.encode("utf-16-le") + b"\0\0"
    return struct.pack("<i", -(len(raw) // 2)) + raw


def locres(version):
    namespaces = {}
    for ns, key, text in ENTRIES:
        namespaces.setdefault(ns, []).append((key, text))
    texts = [text for _, _, text in ENTRIES]
    body = b""
    if version >= 2:
        body += struct.pack("<I", len(ENTRIES))
    body += struct.pack("<I", len(namespaces))
    for ns, keys in namespaces.items():
        body += (struct.pack("<I", 0x1234) if version >= 2 else b"") + fstring(ns) + struct.pack("<I", len(keys))
        for key, text in keys:
            body += (struct.pack("<I", 0x5678) if version >= 2 else b"") + fstring(key) + struct.pack("<I", 0x9ABC)
            body += struct.pack("<i", texts.index(text)) if version >= 1 else fstring(text)
    if version == 0:
        return body
    head = LOCRES_MAGIC + bytes([version])
    table_offset = len(head) + 8 + len(body)
    table = struct.pack("<I", len(texts)) + b"".join(
        fstring(t) + (struct.pack("<i", 1) if version >= 2 else b"") for t in texts)
    return head + struct.pack("<q", table_offset) + body + table


TICKS = int((datetime.datetime(2026, 10, 24, 21, 37, 26) - datetime.datetime(1, 1, 1)).total_seconds()) * 10_000_000


class Gvas:
    """Builds a GVAS file for one layout."""

    def __init__(self, package, custom_versions, inner_array_tag):
        self.package = package
        self.custom_versions = custom_versions
        self.inner_array_tag = inner_array_tag

    def tag(self, name, kind, value, extra=b""):
        guid = b"\0" if self.package >= 503 else b""
        return fstring(name) + fstring(kind) + struct.pack("<ii", len(value), 0) + extra + guid + value

    def struct_tag(self, name, struct_name, value):
        return self.tag(name, "StructProperty", value, fstring(struct_name) + b"\0" * 16)

    def bool_tag(self, name, value):
        guid = b"\0" if self.package >= 503 else b""
        return fstring(name) + fstring("BoolProperty") + struct.pack("<ii", 0, 0) + bytes([value]) + guid

    def props(self):
        item = lambda key, n: (self.tag("Key", "NameProperty", fstring(key)) + self.tag("Count", "IntProperty", struct.pack("<i", n))
                               + fstring("None"))
        items = item("Doors", 3) + item("Keys", 1)
        array = struct.pack("<i", 2)
        if self.inner_array_tag:
            array += self.struct_tag("Records", "Record", b"")
        array += items
        return (self.tag("SaveSlot", "StrProperty", fstring("slot1"))
                + self.tag("Score", "IntProperty", struct.pack("<i", 42))
                + self.bool_tag("Hard", 1)
                + self.struct_tag("SavedAt", "DateTime", struct.pack("<q", TICKS))
                + self.struct_tag("Where", "Vector", struct.pack("<3f", 1.5, -2.0, 3.0))
                + self.tag("Maps", "ArrayProperty", struct.pack("<i", 2) + fstring("Town") + fstring("Lake"), fstring("NameProperty"))
                + self.tag("Records", "ArrayProperty", array, fstring("StructProperty"))
                + self.struct_tag("Player", "PlayerData", self.tag("Health", "FloatProperty", struct.pack("<f", 0.5)) + fstring("None"))
                + fstring("None") + struct.pack("<i", 0))

    def build(self):
        head = b"GVAS" + struct.pack("<ii", 2 if self.custom_versions else 1, self.package)
        head += struct.pack("<HHHI", 4, 27, 2, 0) + fstring("++UE4+Release-4.27")
        if self.custom_versions:
            head += struct.pack("<ii", 3, 2) + (b"\x11" * 16 + struct.pack("<i", 5)) + (b"\x22" * 16 + struct.pack("<i", 9))
        return head + fstring("/Script/Game.MySave_C") + self.props()


def chunked(data, block=64, prefix=b"SAVE"):
    """Unreal's compressed chunk format with zlib blocks, after a game header."""
    blocks = [data[i:i + block] for i in range(0, len(data), block)]
    packed = [zlib.compress(b) for b in blocks]
    out = struct.pack("<QQQQ", 0x9E2A83C1, block, sum(map(len, packed)), len(data))
    out += b"".join(struct.pack("<QQ", len(c), len(u)) for c, u in zip(packed, blocks))
    return prefix + out + b"".join(packed)


def run(script, *args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, os.path.join(BIN, script), *args], capture_output=True, env=env, timeout=60)
    # Windows writes text-mode output with CRLF.
    return (r.returncode, r.stdout.decode("utf-8").replace("\r\n", "\n"),
            r.stderr.decode("utf-8").replace("\r\n", "\n"))


class Files(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def write(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def ok(self, script, *args):
        code, out, err = run(script, *args)
        self.assertEqual(code, 0, err)
        return out


class LocresTest(Files):
    EXPECTED = "\tdoor_title\tOld Door\n\tdoor_hint\tPush\\tthe door\\nslowly\nUI\tgreeting\tOlá\n"

    def test_every_version(self):
        for version in (0, 1, 2):
            with self.subTest(version=version):
                self.assertEqual(self.ok("ue-locres", self.write(f"v{version}.locres", locres(version))), self.EXPECTED)

    def test_filter_on_key_or_text(self):
        path = self.write("f.locres", locres(1))
        self.assertEqual(self.ok("ue-locres", path, "OLÁ", "title"),
                         "\tdoor_title\tOld Door\nUI\tgreeting\tOlá\n")

    def test_truncated(self):
        code, _, err = run("ue-locres", self.write("t.locres", locres(0)[:-5]))
        self.assertEqual(code, 1)
        self.assertIn("not a readable locres", err)


class SaveTest(Files):
    OLD = Gvas(package=500, custom_versions=False, inner_array_tag=False)
    NEW = Gvas(package=522, custom_versions=True, inner_array_tag=True)

    def test_header_and_values(self):
        out = self.ok("ue-save", "props", self.write("old.sav", self.OLD.build()))
        self.assertIn("save version 1, package version 500, engine 4.27.2-0 ++UE4+Release-4.27, "
                      "0 custom versions, class /Script/Game.MySave_C\n", out)
        for line in ("SaveSlot\tStrProperty\t10 bytes\t'slot1'", "Score\tIntProperty\t4 bytes\t42",
                     "Hard\tBoolProperty\t0 bytes\ttrue", "SavedAt\tStructProperty DateTime\t8 bytes\t2026-10-24T21:37:26",
                     "Where\tStructProperty Vector\t12 bytes\t(1.5, -2.0, 3.0)",
                     "Maps\tArrayProperty NameProperty\t22 bytes\t2 items ['Town', 'Lake']",
                     "4 bytes after the property list"):
            self.assertIn(line, out)

    def test_custom_versions_and_guid_bytes(self):
        out = self.ok("ue-save", "props", self.write("new.sav", self.NEW.build()))
        self.assertIn("package version 522, engine 4.27.2-0 ++UE4+Release-4.27, 2 custom versions", out)
        self.assertIn("Score\tIntProperty\t4 bytes\t42", out)

    def test_struct_fields_and_struct_arrays_with_and_without_inner_tag(self):
        for save in (self.OLD, self.NEW):
            with self.subTest(package=save.package):
                out = self.ok("ue-save", "props", self.write(f"d{save.package}.sav", save.build()), "--depth", "1")
                self.assertIn("  [0]\n    Key\tNameProperty\t10 bytes\t'Doors'\n    Count\tIntProperty\t4 bytes\t3\n"
                              "  [1]\n    Key\tNameProperty\t9 bytes\t'Keys'\n", out)
                self.assertIn("Player\tStructProperty PlayerData", out)
                self.assertIn("  Health\tFloatProperty\t4 bytes\t0.5", out)
                self.assertNotIn("unreadable", out)

    def test_compressed_save(self):
        data = self.OLD.build()
        path = self.write("c.sav", chunked(data))
        out = os.path.join(self.tmp.name, "c.gvas")
        self.ok("ue-save", "unpack", path, out)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertIn("Score\tIntProperty\t4 bytes\t42", self.ok("ue-save", "props", path))

    def test_oodle_blocks_need_the_library(self):
        data = bytearray(chunked(self.OLD.build(), block=1 << 20))
        start = data.find(b"\x78", 4 + 48)
        data[start] = 0x8C
        code, _, err = run("ue-save", "props", self.write("o.sav", bytes(data)))
        self.assertEqual(code, 1)
        self.assertIn("pass --oodle", err)

    def malformed(self, name, data):
        code, out, err = run("ue-save", "props", self.write(name, data))
        self.assertEqual(code, 1, out)
        return err

    def test_type_names_are_escaped(self):
        data = self.OLD.build().replace(fstring("IntProperty"), fstring("Int\x1b[2JProperty"), 1)
        out = self.ok("ue-save", "props", self.write("esc.sav", data))
        self.assertNotIn("\x1b", out)
        self.assertIn("Int\\x1b[2JProperty", out)

    def test_negative_size_stops(self):
        data = self.OLD.build()
        i = data.find(fstring("IntProperty")) + len(fstring("IntProperty"))
        bad = data[:i] + struct.pack("<i", -64) + data[i + 4:]
        self.assertIn("declares -64 bytes", self.malformed("neg.sav", bad))

    def test_array_count_larger_than_its_bytes(self):
        data = self.OLD.build()
        i = data.find(fstring("Records") + fstring("ArrayProperty"))
        count_at = data.find(struct.pack("<i", 2) + fstring("Key"), i)
        bad = data[:count_at] + struct.pack("<i", 0x7FFFFFFF) + data[count_at + 4:]
        out = self.ok("ue-save", "props", self.write("count.sav", bad), "--depth", "1")
        self.assertIn("declares 2147483647 items but its bytes end after 2", out)

    def test_zlib_block_larger_than_declared(self):
        data = bytearray(chunked(b"GVAS" + b"\0" * 60))
        sizes = 4 + 32
        c, u = struct.unpack_from("<QQ", data, sizes)
        struct.pack_into("<Q", data, sizes + 8, u - 1)
        struct.pack_into("<Q", data, 4 + 24, u - 1)
        self.assertIn("doesn't hold the 63 bytes", self.malformed("bomb.sav", bytes(data)))

    def test_block_size_out_of_range(self):
        data = bytearray(chunked(self.OLD.build()))
        struct.pack_into("<Q", data, 4 + 8, 1 << 40)
        self.assertIn("block size 1099511627776", self.malformed("block.sav", bytes(data)))

    def test_newer_property_tags_are_refused(self):
        data = self.NEW.build()
        # Version 3 adds a UE5 package version before the engine version.
        ue5 = data[:4] + struct.pack("<ii", 3, 522) + struct.pack("<i", 1012) + data[12:]
        code, out, err = run("ue-save", "props", self.write("ue5.sav", ue5))
        self.assertEqual(code, 1)
        self.assertIn("package version 522/1012", out)
        self.assertIn("UE 5.4 and newer", err)


if __name__ == "__main__":
    unittest.main()
