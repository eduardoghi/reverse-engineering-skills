"""Tests for bin/hsp-unpack against programs built here.

The builder writes a DPMX archive and an HSP3 script with the fields the tool reads,
scrambled the way two real programs were. Run with `python3 -m unittest discover -s tests`.
"""
import importlib.machinery
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "hsp-unpack")
loader = importlib.machinery.SourceFileLoader("hsp_unpack", TOOL)
spec = importlib.util.spec_from_loader("hsp_unpack", loader)
hsp = importlib.util.module_from_spec(spec)
loader.exec_module(hsp)

HEADER_SIZE = 80


def segment(strings):
    """Lay out NUL-terminated strings and return the bytes with the offset of each one."""
    out = bytearray(b"\0")
    offsets = {}
    for text in strings:
        offsets[text] = len(out)
        out += text.encode("cp932") + b"\0"
    return bytes(out), offsets


def script(imports=(), strings=(), extra=b""):
    """A compiled script. imports holds pairs of library and function names."""
    names = [library for library, _ in imports] + [name for _, functions in imports for name in functions] + list(strings)
    data, offsets = segment(names)
    libraries = b"".join(struct.pack("<iiii", 0, offsets[library], 0, 0) for library, _ in imports)
    functions = b""
    for index, (_, called) in enumerate(imports):
        for name in called:
            functions += struct.pack("<hhiiiiii", index, 0, 0, 0, offsets[name], 0, 0, 0)
    # The script's own functions have a negative index and must not be listed.
    functions += struct.pack("<hhiiiiii", -1, 0, 0, 0, 0, 0, 0, 0)
    code = b"\x00" * 16 + extra
    sections = [code, data, b"", b"", libraries, functions]
    words = [0] * 20
    position = HEADER_SIZE
    for field, body in zip((4, 6, 8, 10, 12, 14), sections):
        words[field] = position
        words[field + 1] = len(body)
        position += len(body)
    words[1] = 0x360
    words[3] = position
    body = struct.pack("<20I", *words)
    return b"HSP3" + body[4:] + b"".join(sections)


def scramble(plain, xor_key, add_key, sign):
    out = bytearray()
    previous = 0
    for value in plain:
        difference = (sign * (value - previous)) & 0xFF
        out.append(((difference - add_key) & 0xFF) ^ xor_key)
        previous = value
    return bytes(out)


def program(files, runtime=b"MZ runtime"):
    """A runtime with an archive appended. files holds pairs of name and bytes."""
    table = bytearray()
    body = bytearray()
    for name, blob in files:
        table += name.encode("latin1").ljust(16, b"\0") + struct.pack("<iIII", -1, 1 if name.endswith(".ax") else 0, len(body), len(blob))
        body += blob
    return runtime + b"DPMX" + struct.pack("<III", 16 + len(table), len(files), 0) + bytes(table) + bytes(body)


class ToolCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def write(self, data):
        path = os.path.join(self.folder.name, "keygen.exe")
        with open(path, "wb") as output:
            output.write(data)
        return path

    def run_tool(self, *args):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run([sys.executable, TOOL, *args], capture_output=True, env=env, timeout=60)
        return result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8")


class Decoding(unittest.TestCase):
    def test_every_kind_of_key_comes_back(self):
        plain = script([("USER32.DLL", ["GetParent"])], ["hello there"])
        for xor_key, add_key, sign in ((13, 186, -1), (11, 160, -1), (114, 199, 1), (0, 0, 1), (255, 255, -1)):
            with self.subTest(xor_key=xor_key, add_key=add_key, sign=sign):
                self.assertEqual(hsp.decode_script(scramble(plain, xor_key, add_key, sign)), plain)

    def test_plain_script_is_returned_as_is(self):
        plain = script()
        self.assertEqual(hsp.decode_script(plain), plain)

    def test_wrong_size_in_the_header_is_refused(self):
        plain = bytearray(script())
        struct.pack_into("<I", plain, 12, 1)
        with self.assertRaisesRegex(hsp.HspError, "doesn't decode"):
            hsp.decode_script(scramble(bytes(plain), 13, 186, -1))

    def test_data_that_isnt_a_script_is_refused(self):
        with self.assertRaisesRegex(hsp.HspError, "doesn't decode"):
            hsp.decode_script(bytes(range(200)))

    def test_short_script_is_refused(self):
        with self.assertRaisesRegex(hsp.HspError, "too short"):
            hsp.decode_script(b"\x01\x02")


class Commands(ToolCase):
    def sample(self):
        plain = script([("BASSMOD.dll", ["BASSMOD_Init", "BASSMOD_Free"]), ("R2RJUCE.dll", ["GetMD5A"])], ["Input your name", "Generate"])
        return program([("bg.bmp", b"BM" + bytes(50)), ("start.ax", scramble(plain, 13, 186, -1))]), plain

    def test_list_prints_size_and_name(self):
        code, out, err = self.run_tool("list", self.write(self.sample()[0]))
        self.assertEqual(code, 0, err)
        self.assertIn("52\tbg.bmp", out)
        self.assertIn("\tstart.ax", out)

    def test_script_prints_imports_by_library(self):
        code, out, err = self.run_tool("script", self.write(self.sample()[0]))
        self.assertEqual(code, 0, err)
        lines = out.replace("\r\n", "\n").split("\n")
        self.assertIn("BASSMOD.dll\tBASSMOD_Init\tBASSMOD_Free", lines)
        self.assertIn("R2RJUCE.dll\tGetMD5A", lines)
        self.assertIn("Input your name", lines)

    def test_library_with_no_functions_is_still_listed(self):
        plain = script([("wininet.dll", [])])
        path = self.write(program([("start.ax", plain)]))
        code, out, err = self.run_tool("script", path)
        self.assertEqual(code, 0, err)
        self.assertIn("wininet.dll", out)

    def test_dump_writes_the_decoded_script(self):
        data, plain = self.sample()
        dump = os.path.join(self.folder.name, "start.bin")
        code, out, err = self.run_tool("script", self.write(data), "--dump", dump)
        self.assertEqual(code, 0, err)
        with open(dump, "rb") as source:
            self.assertEqual(source.read(), plain)

    def test_extract_decodes_the_script(self):
        data, plain = self.sample()
        target = os.path.join(self.folder.name, "out")
        code, out, err = self.run_tool("extract", self.write(data), target)
        self.assertEqual(code, 0, err)
        with open(os.path.join(target, "start.ax"), "rb") as source:
            self.assertEqual(source.read(), plain)
        with open(os.path.join(target, "bg.bmp"), "rb") as source:
            self.assertEqual(source.read(), b"BM" + bytes(50))

    def test_names_cant_leave_the_output(self):
        data = program([("..\\..\\evil.txt", b"x"), ("../up.txt", b"y")])
        target = os.path.join(self.folder.name, "out")
        code, out, err = self.run_tool("extract", self.write(data), target)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(os.listdir(target)), 2)
        self.assertFalse(os.path.exists(os.path.join(self.folder.name, "evil.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.folder.name, "up.txt")))

    def test_control_characters_are_escaped(self):
        plain = script(strings=["red\x1b[31m"])
        code, out, err = self.run_tool("script", self.write(program([("start.ax", plain)])))
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\u001b[31m", out)


class Failures(ToolCase):
    def test_not_an_hsp_program(self):
        code, out, err = self.run_tool("list", self.write(b"MZ" + bytes(4096)))
        self.assertEqual(code, 2)
        self.assertIn("no DPMX archive", err)

    def test_the_id_elsewhere_in_the_runtime_is_skipped(self):
        # Three entries and a table size that doesn't fit them, so this can't be the archive.
        decoy = b"DPMX" + struct.pack("<III", 20, 3, 0) + bytes(120)
        data = program([("bg.bmp", b"BM")], runtime=b"MZ" + decoy)
        code, out, err = self.run_tool("list", self.write(data))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.replace("\r\n", "\n"), "2\tbg.bmp\n")

    def test_entry_past_the_end_is_refused(self):
        data = bytearray(program([("bg.bmp", b"BM")]))
        position = data.index(b"bg.bmp") + 28
        struct.pack_into("<I", data, position, 1 << 30)
        code, out, err = self.run_tool("list", self.write(bytes(data)))
        self.assertEqual(code, 2)
        self.assertIn("past the end", err)

    def test_archive_without_a_script(self):
        code, out, err = self.run_tool("script", self.write(program([("bg.bmp", b"BM")])))
        self.assertEqual(code, 2)
        self.assertIn("no compiled script", err)

    def test_section_past_the_end_is_refused(self):
        plain = bytearray(script())
        struct.pack_into("<I", plain, 6 * 4, 1 << 30)
        code, out, err = self.run_tool("script", self.write(program([("start.ax", bytes(plain))])))
        self.assertEqual(code, 2)
        self.assertIn("past the end", err)


if __name__ == "__main__":
    unittest.main()
