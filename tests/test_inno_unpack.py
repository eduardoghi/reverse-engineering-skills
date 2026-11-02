"""Tests for bin/inno-unpack against installers built here.

The builder writes the offset table, the compressed blocks with a CRC every
4 KiB, the records of each format and the file chunks, as the Inno Setup
compiler does. Record sizes come from the table in the tool, so these tests prove
the logic for every format but not the numbers in the table. Those were checked
against Shared.Struct.pas and the official installers of each release. Run with
`python3 -m unittest discover -s tests`.
"""
import bz2
import hashlib
import importlib.machinery
import importlib.util
import lzma
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "inno-unpack")
loader = importlib.machinery.SourceFileLoader("inno_unpack", TOOL)
spec = importlib.util.spec_from_loader("inno_unpack", loader)
inno = importlib.util.module_from_spec(spec)
loader.exec_module(inno)

LDR_ID = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a"
METHODS = {"stored": 0, "zip": 1, "bzip2": 2, "lzma": 3, "lzma2": 4}
LZMA_PROPS = bytes([0x5D]) + struct.pack("<I", 1 << 20)
LZMA_FILTER = {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}


def apply_call_filter(data):
    """TransformCallInstructions with Encode set, in blocks of 64 KiB like the compiler."""
    out = bytearray(data)
    for base in range(0, len(out), 0x10000):
        block = out[base:base + 0x10000]
        limit = len(block) - 4
        i = 0
        while i < limit:
            if block[i] in (0xE8, 0xE9):
                i += 1
                if block[i + 3] in (0x00, 0xFF):
                    address = (base + i + 4) & 0xFFFFFF
                    relative = block[i] | block[i + 1] << 8 | block[i + 2] << 16
                    if relative & 0x800000:
                        block[i + 3] ^= 0xFF
                    relative = (relative + address) & 0xFFFFFF
                    block[i:i + 3] = relative.to_bytes(3, "little")
                i += 4
            else:
                i += 1
        out[base:base + 0x10000] = block
    return bytes(out)


def code_like(size, seed=1):
    """Bytes full of CALL and JMP with operands near zero and past the sign bit."""
    out = bytearray()
    value = seed
    while len(out) < size:
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        operand = value % 0x2000
        kind = value >> 13 & 3
        if kind == 0:
            out += b"\xE8" + struct.pack("<I", operand)
        elif kind == 1:
            out += b"\xE9" + struct.pack("<i", -operand - 1)
        elif kind == 2:
            out += b"\xE8" + struct.pack("<I", operand | 0x800000)
        else:
            out += b"\x90\x48\x89\xE5" + struct.pack("<I", value)
    return bytes(out[:size])


def compress(data, method):
    if method == "stored":
        return data
    if method == "zip":
        return zlib.compress(data)
    if method == "bzip2":
        return bz2.compress(data)
    if method == "lzma":
        return LZMA_PROPS + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[LZMA_FILTER])
    return bytes([22]) + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[
        {"id": lzma.FILTER_LZMA2, "dict_size": 2 << 22}])


def text(value):
    raw = value.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def blob(value):
    return struct.pack("<I", len(value)) + value


def entry(strings, count, fixed, ansi=()):
    filled = list(strings) + [""] * (count - len(strings))
    return b"".join(text(value) for value in filled) + b"".join(blob(value) for value in ansi) + bytes(fixed)


def block(data, wide, compressed=True):
    """A compressed block. Stored sizes are 32 bits before 6.7."""
    payload = LZMA_PROPS + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[LZMA_FILTER]) if compressed else data
    stored = bytearray()
    for pos in range(0, len(payload), 4096):
        piece = payload[pos:pos + 4096]
        stored += struct.pack("<I", zlib.crc32(piece)) + piece
    header = struct.pack("<Q" if wide else "<I", len(stored)) + bytes([1 if compressed else 0])
    return struct.pack("<I", zlib.crc32(header)) + header + bytes(stored)


def table(version, offset0, offset1):
    if version >= 2:
        body = LDR_ID + struct.pack("<I", 2) + struct.pack("<qqIiqqI", 0, 0, 0, 0, offset0, offset1, 0)
    else:
        body = LDR_ID + struct.pack("<IIIIiII", 1, 0, 0, 0, 0, offset0, offset1)
    return body + struct.pack("<I", zlib.crc32(body))


class FileSpec:
    def __init__(self, dest, data=b"", call_filter=False, language="", check="", regserver=False, source="",
                 external=False, uninstaller=False, location=None):
        self.dest, self.data, self.call_filter = dest, data, call_filter
        self.language, self.check, self.regserver = language, check, regserver
        self.source, self.external, self.uninstaller = source, external, uninstaller
        self.location = location


def build(version="7.1.1", files=(), method="lzma", solid=True, run=(), uninstall_run=(), registry=(), ini=(),
          delete=(), icons=(), code=b"", encryption=0, encrypted_chunk=False, embedded=True, bad_digest=False,
          uncompressed_blocks=False, unstored_chunk=False):
    layout = inno.LAYOUTS[version]
    numbers = tuple(int(part) for part in version.split("."))
    wide_blocks = numbers >= (6, 7)
    modern = numbers >= (6, 5)
    files = list(files)

    stored = [item for item in files if not item.external and not item.uninstaller and item.location is None]
    indexes = {id(item): index for index, item in enumerate(stored)}
    for item in files:
        if item.location is not None:
            indexes[id(item)] = indexes[id(item.location)]

    area = bytearray()
    locations = bytearray()
    chunks = []
    if solid:
        solid_data = b"".join(apply_call_filter(item.data) if item.call_filter else item.data for item in stored)
        chunks.append((0, compress(solid_data, "stored" if unstored_chunk else method)))
    suboffset = 0
    start = 0
    for item in stored:
        filtered = apply_call_filter(item.data) if item.call_filter else item.data
        if not solid:
            start = len(area)
            area += b"zlb\x1a" + compress(filtered, method)
            size = len(area) - start - 4
            suboffset = 0
        else:
            size = len(chunks[0][1])
        wide = layout.location_fixed == 89
        old_flags = layout.location_fixed in (74, 75, 87)
        digest_name, digest_size = ("sha1", 20) if layout.location_fixed in (74, 75) else ("sha256", 32)
        digest = hashlib.new(digest_name, item.data).digest()
        if bad_digest:
            digest = bytes(digest_size)
        call_bit, encrypted_bit, compressed_bit = (4, 6, 7) if old_flags else (2, 3, 4)
        flags = 0
        if item.call_filter:
            flags |= 1 << call_bit
        if encrypted_chunk:
            flags |= 1 << encrypted_bit
        if method != "stored" and not unstored_chunk:
            flags |= 1 << compressed_bit
        record = struct.pack("<ii", 0, 0) + struct.pack("<Q" if wide else "<I", start)
        record += struct.pack("<qqq", suboffset, len(item.data), size) + digest + bytes(16)
        record += flags.to_bytes(2 if old_flags else 1, "little")
        record += bytes(layout.location_fixed - len(record))
        locations += record
        suboffset += len(filtered)
    if solid:
        area += b"zlb\x1a" + chunks[0][1]

    has_issig = layout.file_ansi > 0
    counts = [1, 0, 0, 0, 0, 0, 0] + ([0] if has_issig else [])
    counts += [len(files), len(stored), len(icons), len(ini), len(registry), len(delete), 0, len(run), len(uninstall_run)]
    header_fixed = bytearray(layout.header_fixed)
    struct.pack_into(f"<{len(counts)}i", header_fixed, 0, *counts)
    header_fixed[layout.compress_offset] = METHODS[method]

    setup0 = entry(["Demo App", "Demo App 1.0", "demo-id", "", "Example Publisher", "", "", "", "", "1.0"],
                   layout.header_strings, header_fixed, ansi=(b"", b"", b"", code))
    setup0 += entry(["english"], layout.language_strings, bytes(layout.language_fixed), ansi=(b"", b"", b"", b""))
    for item in files:
        fixed = bytearray(layout.file_fixed)
        offset = 33 * layout.file_ansi
        location = -1 if item.external or item.uninstaller else indexes[id(item)]
        struct.pack_into("<i", fixed, offset + 20, location)
        if item.regserver:
            fixed[offset + 38 + (1 if layout.file_fixed == 81 else 0)] = 1 << 4
        if item.uninstaller:
            fixed[-1] = 1
        strings = [item.source, item.dest, "", "", "", "", item.language, item.check]
        setup0 += entry(strings, layout.file_strings, fixed, ansi=(b"",) * layout.file_ansi)
    for strings in icons:
        setup0 += entry(strings, 13, bytes(layout.icon_fixed))
    for strings in ini:
        setup0 += entry(strings, 10, bytes(21))
    for root, kind, strings in registry:
        fixed = bytearray(layout.registry_fixed)
        struct.pack_into("<I", fixed, 20, root)
        fixed[26] = kind
        setup0 += entry(strings, 9, fixed)
    for kind, name in delete:
        fixed = bytearray(21)
        fixed[20] = kind
        setup0 += entry([name], 7, fixed)
    for entries in (run, uninstall_run):
        for strings, wait, options in entries:
            fixed = bytearray(layout.run_fixed)
            fixed[24] = wait
            fixed[26 if layout.run_fixed == 28 else 25] = options
            setup0 += entry(strings, layout.run_strings, fixed)
    setup0 += struct.pack("<i", 0)

    data = b"Inno Setup Setup Data (" + version.encode() + b")"
    data += bytes(64 - len(data))
    if modern:
        body = bytes([encryption]) + bytes(48)
        data += struct.pack("<I", zlib.crc32(body)) + body
    data += block(setup0, wide_blocks, compressed=not uncompressed_blocks)
    data += block(bytes(locations), wide_blocks, compressed=not uncompressed_blocks)

    # The ID also sits in the loader code, without a table behind it.
    stub = b"MZ" + bytes(62) + LDR_ID + struct.pack("<I", 1) + bytes(40)
    size = 2 if modern else 1
    offset0 = len(stub) + (64 if modern else 44)
    offset1 = offset0 + len(data)
    return stub + table(size, offset0, offset1 if embedded else 0) + data + bytes(area)


class ToolCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def write(self, data, name="setup.exe"):
        path = os.path.join(self.folder.name, name)
        with open(path, "wb") as output:
            output.write(data)
        return path

    def run_tool(self, *args):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run([sys.executable, TOOL, *args], capture_output=True, env=env, timeout=120)
        return result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8")

    def extract(self, data, *args):
        path = self.write(data)
        out = os.path.join(self.folder.name, "out")
        return (out, *self.run_tool("extract", path, out, *args))

    def read(self, *parts):
        with open(os.path.join(self.folder.name, "out", *parts), "rb") as source:
            return source.read()


class EveryFormat(ToolCase):
    def test_each_format_lists_and_extracts(self):
        program = code_like(200000)
        for version in inno.LAYOUTS:
            with self.subTest(version=version):
                files = [FileSpec("{app}\\app.exe", program, call_filter=True), FileSpec("{app}\\readme.txt", b"hello"),
                         FileSpec("{tmp}\\sub\\data.bin", bytes(range(256)) * 300), FileSpec("", uninstaller=True),
                         FileSpec("{app}\\more.bin", source="https://example.com/more.bin", external=True)]
                data = build(version, files, run=[(["{app}\\app.exe", "/silent"], 0, 0)],
                             registry=[(0x80000002, 1, ["Software\\Demo", "Path", "{app}"])])
                path = self.write(data, f"setup-{version}.exe")
                code, out, err = self.run_tool("info", path)
                self.assertEqual(code, 0, err)
                self.assertIn(f"format\t{version}", out)
                self.assertIn("app\tDemo App", out)
                self.assertIn("publisher\tExample Publisher", out)
                self.assertIn("run\t1 on install", out)

                code, out, err = self.run_tool("list", path)
                self.assertEqual(code, 0, err)
                old = inno.LAYOUTS[version].location_fixed in (74, 75)
                digest = hashlib.sha1(program) if old else hashlib.sha256(program)
                self.assertIn(f"{len(program)}\t{digest.name}:{digest.hexdigest()}\t{{app}}\\app.exe", out)
                self.assertIn("-\tuninstaller", out)
                self.assertIn("-\texternal\t{app}\\more.bin\tsource=https://example.com/more.bin", out)

                out_dir = os.path.join(self.folder.name, f"out-{version}")
                code, out, err = self.run_tool("extract", path, out_dir)
                self.assertEqual(code, 0, err + out)
                self.assertIn("3 files written", out)
                with open(os.path.join(out_dir, "app", "app.exe"), "rb") as source:
                    self.assertEqual(source.read(), program)
                with open(os.path.join(out_dir, "tmp", "sub", "data.bin"), "rb") as source:
                    self.assertEqual(source.read(), bytes(range(256)) * 300)
                code, out, err = self.run_tool("actions", path)
                self.assertEqual(code, 0, err)
                self.assertIn("name={app}\\app.exe\tparams=/silent", out)
                self.assertIn("root=HKLM\tsubkey=Software\\Demo\tname=Path\ttype=string\tdata={app}", out)

    def test_blocks_can_be_stored_uncompressed(self):
        path = self.write(build("6.0.0", [FileSpec("{app}\\a.txt", b"abc")], uncompressed_blocks=True))
        code, out, err = self.run_tool("list", path)
        self.assertEqual(code, 0, err)
        self.assertIn("{app}\\a.txt", out)


class Compression(ToolCase):
    def test_each_method(self):
        program = code_like(150000)
        for method in METHODS:
            for solid in (True, False):
                with self.subTest(method=method, solid=solid):
                    files = [FileSpec("{app}\\a.exe", program, call_filter=True), FileSpec("{app}\\b.txt", b"second file")]
                    path = self.write(build("7.1.1", files, method=method, solid=solid), f"{method}-{solid}.exe")
                    out_dir = os.path.join(self.folder.name, f"out-{method}-{solid}")
                    code, out, err = self.run_tool("extract", path, out_dir)
                    self.assertEqual(code, 0, err + out)
                    with open(os.path.join(out_dir, "app", "a.exe"), "rb") as source:
                        self.assertEqual(source.read(), program)
                    with open(os.path.join(out_dir, "app", "b.txt"), "rb") as source:
                        self.assertEqual(source.read(), b"second file")

    def test_chunk_stored_inside_a_compressed_installer(self):
        files = [FileSpec("{app}\\photo.jpg", b"\xff\xd8" * 1000)]
        out, code, stdout, err = self.extract(build("7.1.1", files, unstored_chunk=True))
        self.assertEqual(code, 0, err + stdout)
        self.assertEqual(self.read("app", "photo.jpg"), b"\xff\xd8" * 1000)


class CallFilter(unittest.TestCase):
    def undo(self, data):
        buffer = bytearray()
        for base in range(0, len(data), 0x10000):
            block_data = bytearray(data[base:base + 0x10000])
            inno.undo_call_filter(block_data, base)
            buffer += block_data
        return bytes(buffer)

    def test_round_trip_across_blocks(self):
        for size in (0, 1, 4, 5, 6, 65535, 65536, 65537, 300000):
            with self.subTest(size=size):
                original = code_like(size)
                self.assertEqual(self.undo(apply_call_filter(original)), original)

    def test_known_values(self):
        # The CALL is at offset 0 and its operand at 1, so the address is 5.
        self.assertEqual(self.undo(b"\xE8\x15\x00\x00\x00\x90\x90\x90\x90\x90"),
                         b"\xE8\x10\x00\x00\x00\x90\x90\x90\x90\x90")

    def test_high_byte_flips_with_bit_23(self):
        original = b"\xE8\xF0\xFF\xFF\xFF" + bytes(8)
        filtered = apply_call_filter(original)
        self.assertEqual(filtered[4], 0x00)
        self.assertEqual(self.undo(filtered), original)

    def test_operands_with_other_high_bytes_stay(self):
        data = b"\xE8\x11\x22\x33\x44" + bytes(8)
        self.assertEqual(self.undo(data), data)

    def test_no_change_in_the_last_bytes_of_a_block(self):
        self.assertEqual(self.undo(b"\x90\xE8\x01\x00\x00"), b"\x90\xE8\x01\x00\x00")


class Destinations(ToolCase):
    def test_paths_stay_inside_the_output(self):
        files = [FileSpec("{app}\\..\\..\\..\\evil.txt", b"1"), FileSpec("C:\\Windows\\System32\\evil.dll", b"2"),
                 FileSpec("\\\\server\\share\\evil.txt", b"3"), FileSpec("/etc/evil", b"4"),
                 FileSpec("{app}\\sub/../../evil2.txt", b"5"), FileSpec("{code:Get|x}\\a?b*c.txt", b"6"),
                 FileSpec("{app}\\CON.txt", b"7"), FileSpec("{app}\\trailing. ", b"8"), FileSpec("...", b"9")]
        out, code, stdout, err = self.extract(build("7.1.1", files))
        self.assertEqual(code, 0, err + stdout)
        written = {}
        for root, _, names in os.walk(out):
            for name in names:
                with open(os.path.join(root, name), "rb") as source:
                    written[os.path.relpath(os.path.join(root, name), out).replace(os.sep, "/")] = source.read()
        self.assertEqual(len(written), len(files))
        self.assertEqual(written["app/evil.txt"], b"1")
        self.assertEqual(written["C_/Windows/System32/evil.dll"], b"2")
        self.assertEqual(written["server/share/evil.txt"], b"3")
        self.assertEqual(written["etc/evil"], b"4")
        self.assertEqual(written["app/sub/evil2.txt"], b"5")
        self.assertEqual(written["code_Get_x/a_b_c.txt"], b"6")
        self.assertEqual(written["app/_CON.txt"], b"7")
        self.assertEqual(written["app/trailing"], b"8")
        self.assertEqual(written["unnamed"], b"9")
        self.assertFalse(os.path.exists(os.path.join(self.folder.name, "evil.txt")))

    def test_symlink_in_the_output_cant_redirect_a_file(self):
        out = os.path.join(self.folder.name, "out")
        outside = os.path.join(self.folder.name, "outside")
        os.makedirs(out)
        os.makedirs(outside)
        try:
            os.symlink(outside, os.path.join(out, "app"), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks aren't available here")
        path = self.write(build("7.1.1", [FileSpec("{app}\\evil.txt", b"x")]))
        code, stdout, err = self.run_tool("extract", path, out)
        self.assertEqual(code, 2)
        self.assertIn("leaves the output directory", err)
        self.assertEqual(os.listdir(outside), [])

    def test_variants_of_one_destination_are_all_kept(self):
        files = [FileSpec("{app}\\text.txt", b"english", language="english"),
                 FileSpec("{app}\\text.txt", b"german", language="german")]
        out, code, stdout, err = self.extract(build("7.1.1", files))
        self.assertEqual(code, 0, err + stdout)
        self.assertEqual(sorted([self.read("app", "text.txt"), self.read("app", "text.txt~2")]), [b"english", b"german"])

    def test_one_location_with_two_destinations(self):
        shared = FileSpec("{app}\\one.dll", b"shared bytes")
        files = [shared, FileSpec("{sys}\\two.dll", location=shared)]
        out, code, stdout, err = self.extract(build("7.1.1", files))
        self.assertEqual(code, 0, err + stdout)
        self.assertIn("2 files written", stdout)
        self.assertEqual(self.read("app", "one.dll"), b"shared bytes")
        self.assertEqual(self.read("sys", "two.dll"), b"shared bytes")

    def test_only_filters_by_destination(self):
        files = [FileSpec("{app}\\Keep.EXE", b"1"), FileSpec("{app}\\skip.txt", b"2"), FileSpec("{tmp}\\keep2.exe", b"3")]
        out, code, stdout, err = self.extract(build("7.1.1", files), "--only", "*.exe")
        self.assertEqual(code, 0, err + stdout)
        self.assertEqual(self.read("app", "Keep.EXE"), b"1")
        self.assertEqual(self.read("tmp", "keep2.exe"), b"3")
        self.assertFalse(os.path.exists(os.path.join(out, "app", "skip.txt")))

    def test_files_in_a_solid_chunk_can_be_skipped(self):
        files = [FileSpec("{app}\\first.bin", code_like(100000), call_filter=True),
                 FileSpec("{app}\\second.bin", code_like(100000, seed=2), call_filter=True)]
        out, code, stdout, err = self.extract(build("7.1.1", files), "--only", "*second*")
        self.assertEqual(code, 0, err + stdout)
        self.assertEqual(self.read("app", "second.bin"), code_like(100000, seed=2))


class Failures(ToolCase):
    def test_hash_mismatch_keeps_nothing(self):
        out, code, stdout, err = self.extract(build("7.1.1", [FileSpec("{app}\\a.txt", b"data")], bad_digest=True))
        self.assertEqual(code, 1)
        self.assertIn("hash mismatch", err)
        self.assertIn("1 failed", stdout)
        self.assertEqual([name for _, _, names in os.walk(out) for name in names], [])

    def test_encrypted_files_are_listed_but_not_extracted(self):
        path = self.write(build("7.1.1", [FileSpec("{app}\\a.txt", b"data")], encryption=1, encrypted_chunk=True))
        code, out, err = self.run_tool("info", path)
        self.assertEqual(code, 0, err)
        self.assertIn("encryption\tfiles", out)
        code, out, err = self.run_tool("list", path)
        self.assertEqual(code, 0, err)
        self.assertIn("{app}\\a.txt", out)
        code, out, err = self.run_tool("extract", path, os.path.join(self.folder.name, "out"))
        self.assertEqual(code, 1)
        self.assertIn("encrypted, skipped", err)

    def test_older_encrypted_files_come_from_the_location_flag(self):
        path = self.write(build("6.4.3", [FileSpec("{app}\\a.txt", b"data")], encrypted_chunk=True))
        code, out, err = self.run_tool("info", path)
        self.assertEqual(code, 0, err)
        self.assertIn("encryption\tfiles", out)

    def test_full_encryption_stops_with_a_reason(self):
        code, out, err = self.run_tool("info", self.write(build("7.1.1", encryption=2)))
        self.assertEqual(code, 2)
        self.assertIn("password", err)

    def test_external_data_is_refused_when_extracting(self):
        path = self.write(build("7.1.1", [FileSpec("{app}\\a.txt", b"data")], embedded=False))
        code, out, err = self.run_tool("info", path)
        self.assertEqual(code, 0, err)
        self.assertIn("embedded data\tno", out)
        code, out, err = self.run_tool("extract", path, os.path.join(self.folder.name, "out"))
        self.assertEqual(code, 2)
        self.assertIn("setup-1.bin", err)

    def replace_id(self, old, new):
        data = build("7.1.1", [FileSpec("{app}\\a.txt", b"x")])
        marker = f"Inno Setup Setup Data ({old})".encode()
        return data.replace(marker, f"Inno Setup Setup Data ({new})".encode().ljust(len(marker), b"\0"))

    def test_format_older_than_6_points_to_innoextract(self):
        code, out, err = self.run_tool("info", self.write(self.replace_id("7.1.1", "5.6.2")))
        self.assertEqual(code, 2)
        self.assertIn("innoextract", err)

    def test_format_newer_than_the_table_is_refused(self):
        code, out, err = self.run_tool("info", self.write(self.replace_id("7.1.1", "9.9.9")))
        self.assertEqual(code, 2)
        self.assertIn("isn't known", err)

    def test_not_an_installer(self):
        code, out, err = self.run_tool("info", self.write(b"MZ" + bytes(4096)))
        self.assertEqual(code, 2)
        self.assertIn("no Inno Setup offset table", err)

    def test_empty_file(self):
        code, out, err = self.run_tool("info", self.write(b""))
        self.assertEqual(code, 2)
        self.assertIn("empty", err)

    def test_corrupt_block_is_caught_by_the_crc(self):
        data = bytearray(build("7.1.1", [FileSpec("{app}\\a.txt", b"x")]))
        position = data.index(b"Inno Setup Setup Data") + 64 + 53 + 13 + 4 + 40
        data[position] ^= 0xFF
        code, out, err = self.run_tool("info", self.write(bytes(data)))
        self.assertEqual(code, 2)
        self.assertIn("bad CRC", err)

    def test_wrong_layout_is_reported_instead_of_garbage(self):
        data = build("6.5.0", [FileSpec("{app}\\a.txt", b"x")])
        # 6.5.2 reads the same strings but a longer header and location record.
        path = self.write(data.replace(b"Setup Data (6.5.0)", b"Setup Data (6.5.2)"))
        code, out, err = self.run_tool("info", path)
        self.assertEqual(code, 2)
        self.assertIn("inno-unpack:", err)


class Output(ToolCase):
    def test_actions_show_what_the_installer_does(self):
        files = [FileSpec("{sys}\\plugin.dll", b"dll", regserver=True),
                 FileSpec("{app}\\tool.zip", source="https://example.com/tool.zip", external=True)]
        data = build("7.1.1", files,
                     run=[(["{tmp}\\setup.exe", "/quiet", "{tmp}", "", "", "open", "", "", "", "", "IsWin64"], 1, 1 | 4)],
                     uninstall_run=[(["{app}\\clean.exe"], 0, 0)],
                     registry=[(0x80000001, 3, ["Software\\Run", "Start", "1"]), (1, 0, ["Software\\Auto"]),
                               (0x12345678, 99, ["Software\\Odd"])],
                     ini=[["{win}\\a.ini", "main", "key", "value"]],
                     delete=[(0, "{app}\\old.txt")],
                     icons=[["{group}\\Tool", "{app}\\tool.exe", "/run"]])
        code, out, err = self.run_tool("actions", self.write(data))
        self.assertEqual(code, 0, err)
        self.assertIn("[Run]\nname={tmp}\\setup.exe\tparams=/quiet\tworkingdir={tmp}\tverb=open\t"
                      "flags=shellexec postinstall nowait\tcheck=IsWin64\n", out.replace("\r\n", "\n"))
        self.assertIn("[UninstallRun]", out)
        self.assertIn("name={app}\\clean.exe", out)
        self.assertIn("root=HKCU\tsubkey=Software\\Run\tname=Start\ttype=dword\tdata=1", out)
        self.assertIn("root=HKA\tsubkey=Software\\Auto\ttype=none", out)
        self.assertIn("root=0x12345678\tsubkey=Software\\Odd\ttype=99", out)
        self.assertIn("file={win}\\a.ini\tsection=main\tkey=key\tvalue=value", out)
        self.assertIn("name={app}\\old.txt\ttype=files", out)
        self.assertIn("name={group}\\Tool\ttarget={app}\\tool.exe\tparams=/run", out)
        self.assertIn("[RegisterServer]", out)
        self.assertIn("dest={sys}\\plugin.dll", out)
        self.assertIn("[External]", out)
        self.assertIn("source=https://example.com/tool.zip\tdest={app}\\tool.zip", out)

    def test_flags_sit_after_the_bitness_only_where_it_exists(self):
        for version in ("6.7.0", "7.0.0.1", "7.0.0.3", "7.1.1"):
            with self.subTest(version=version):
                data = build(version, [FileSpec("{sys}\\a.dll", b"x", regserver=True)],
                             run=[(["a.exe"], 0, 1)])
                code, out, err = self.run_tool("actions", self.write(data, f"{version}.exe"))
                self.assertEqual(code, 0, err)
                self.assertIn("flags=shellexec", out)
                self.assertIn("dest={sys}\\a.dll", out)

    def test_control_characters_are_escaped(self):
        files = [FileSpec("{app}\\\x1b[31mred\tname\n.txt", b"x")]
        code, out, err = self.run_tool("list", self.write(build("7.1.1", files)))
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\u001b[31mred\\tname\\n.txt", out)

    def test_list_shows_conditions(self):
        files = [FileSpec("{app}\\a.txt", b"x", language="german", check="IsAdmin")]
        code, out, err = self.run_tool("list", self.write(build("7.1.1", files)))
        self.assertEqual(code, 0, err)
        self.assertIn("{app}\\a.txt\tlanguages=german\tcheck=IsAdmin", out)

    def test_code_lists_imports_names_and_strings(self):
        script = (b"IFPS\x17\x00\x00\x00SHELLEXEC\x00\x00INITIALIZESETUP\x00" +
                  b"dll:kernel32.dll\x00GetTickCount\x00\x00" + b"class:TWIZARDFORM|BEVEL|\x00" +
                  "cmd.exe /c evil".encode("utf-16-le") + b"\x00\x00https://example.com/payload\x00")
        path = self.write(build("7.1.1", code=script))
        dump = os.path.join(self.folder.name, "script.bin")
        code, out, err = self.run_tool("code", path, "--dump", dump)
        self.assertEqual(code, 0, err)
        self.assertIn("dll:kernel32.dll GetTickCount", out)
        self.assertIn("class:TWIZARDFORM|BEVEL|", out)
        self.assertIn("SHELLEXEC", out)
        self.assertIn("INITIALIZESETUP", out)
        self.assertIn("cmd.exe /c evil", out)
        self.assertIn("https://example.com/payload", out)
        with open(dump, "rb") as source:
            self.assertEqual(source.read(), script)

    def test_code_absent(self):
        code, out, err = self.run_tool("code", self.write(build("7.1.1")))
        self.assertEqual(code, 0, err)
        self.assertIn("no [Code] section", out)


if __name__ == "__main__":
    unittest.main()
