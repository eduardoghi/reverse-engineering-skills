"""Tests for bin/nsis-script against installers built here.

The builder writes the first header and a script header with the block table, the
entries and a Unicode string table, in each layout the tool reads. Run with
`python3 -m unittest discover -s tests`.
"""
import lzma
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "nsis-script")
MAGIC = b"\xef\xbe\xad\xdeNullsoftInst"
TEMP = "\x03肙"  # $TEMP as NSIS stores it, code 3 and the number 25 split in 7-bit runs
EXTRACT, DELETE, CREATE_DIR, EXEC, RET, WRITE_REG, SLEEP = 20, 21, 11, 41, 1, 51, 7


def table(strings):
    out = "\0".encode("utf-16-le")
    offsets = {}
    position = 1
    for text in strings:
        offsets[text] = position
        encoded = text.encode("utf-16-le", "surrogatepass") + b"\0\0"
        out += encoded
        position += len(encoded) // 2
    return out, offsets


def header(entries, ansi=False):
    """entries holds an opcode and up to six parameters, where strings go in the table."""
    strings = [item for entry in entries for item in entry[1:] if isinstance(item, str)]
    raw_table, offsets = table(strings)
    if ansi:
        raw_table = b"x" + raw_table
    packed = b""
    for entry in entries:
        fields = [entry[0]] + [offsets[item] if isinstance(item, str) else item for item in entry[1:]]
        packed += struct.pack("<7i", *(fields + [0] * (7 - len(fields))))
    top = 4 + 8 * 8
    blocks = [(top, 0), (top, 0), (top, len(entries)), (top + len(packed), 0), (top + len(packed) + len(raw_table), 0), (0, 0), (0, 0), (0, 0)]
    return struct.pack("<I", 0) + b"".join(struct.pack("<II", *block) for block in blocks) + packed + raw_table


def lzma_data(data, dictionary=1 << 20):
    props = bytes([0x5D]) + struct.pack("<I", dictionary)
    return props + lzma.compress(data, format=lzma.FORMAT_RAW, filters=[
        {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": dictionary}])


def deflate_data(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def installer(block, layout):
    size = len(block)
    if layout == "stored":
        body = struct.pack("<I", size) + block
    elif layout == "solid":
        body = lzma_data(struct.pack("<I", size) + block)
    elif layout == "solid-looks-flagged":
        # Dictionary of 8 MiB, the default, whose props read as 0x8000005d.
        body = lzma_data(struct.pack("<I", size) + block, 1 << 23)
    elif layout == "lzma":
        packed = lzma_data(block)
        body = struct.pack("<I", 0x80000000 | len(packed)) + packed
    else:
        packed = deflate_data(block)
        body = struct.pack("<I", 0x80000000 | len(packed)) + packed
    first = struct.pack("<I", 2) + MAGIC + struct.pack("<II", size, len(body) + 28)
    return b"MZ" + bytes(64) + first + body


ACTIONS = [(CREATE_DIR, TEMP), (EXTRACT, 0, "keygen.exe"), (EXEC, TEMP + "\\keygen.exe", 0, 1), (DELETE, TEMP + "\\keygen.exe"),
           (WRITE_REG, -0x7FFFFFFF, "Software\\Run", "Start", "evil.exe"), (SLEEP, 5), (RET,)]


class ToolCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def run_tool(self, data, *args):
        path = os.path.join(self.folder.name, "setup.exe")
        with open(path, "wb") as output:
            output.write(data)
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run([sys.executable, TOOL, path, *args], capture_output=True, env=env, timeout=60)
        return result.returncode, result.stdout.decode("utf-8").replace("\r\n", "\n"), result.stderr.decode("utf-8")


class Layouts(ToolCase):
    def test_each_way_of_storing_the_header(self):
        block = header(ACTIONS)
        for layout in ("stored", "solid", "solid-looks-flagged", "lzma", "deflate"):
            with self.subTest(layout=layout):
                code, out, err = self.run_tool(installer(block, layout))
                self.assertEqual(code, 0, err)
                self.assertIn("Exec\t$TEMP\\keygen.exe", out)


class Output(ToolCase):
    def result(self, entries=ACTIONS):
        code, out, err = self.run_tool(installer(header(entries), "solid"))
        self.assertEqual(code, 0, err)
        return out

    def test_actions_are_printed_in_order(self):
        out = self.result()
        lines = out.split("\n")
        self.assertEqual(lines[:5], ["CreateDirectory\t$TEMP", "ExtractFile\tkeygen.exe", "Exec\t$TEMP\\keygen.exe",
                                     "DeleteFile\t$TEMP\\keygen.exe", "WriteReg\tSoftware\\Run\tStart\tevil.exe"])

    def test_every_instruction_is_counted(self):
        out = self.result()
        section = out[out.index("[Instructions]"):]
        self.assertIn("1\tExec", section)
        self.assertIn("1\tReturn", section)
        self.assertIn("1\tSleep", section)

    def test_flow_control_isnt_printed_as_an_action(self):
        out = self.result()
        self.assertNotIn("Sleep", out[:out.index("[Instructions]")])

    def test_unknown_opcode_is_counted_by_number(self):
        self.assertIn("1\top99", self.result([(99, 0)]))

    def test_variables_are_spelled_out(self):
        cases = (("\x03耕", "$INSTDIR"), ("\x03肀", "$0"), ("\x03肁", "$1"), ("\x03肊", "$R0"), ("\x03肙", "$TEMP"))
        for stored, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(f"DeleteFile\t{expected}\\a.txt", self.result([(DELETE, stored + "\\a.txt")]))

    def test_numbers_past_127_use_the_second_run_of_bits(self):
        # 200 is 72 in the low 7 bits and 1 in the next 7, each with its high bit set.
        self.assertIn("DeleteFile\t$var200\\a.txt", self.result([(DELETE, "\x03臈\\a.txt")]))

    def test_shell_folders_and_language_strings_stay_visible(self):
        out = self.result([(DELETE, "\x02₁\\a.txt"), (DELETE, "\x01肂")])
        self.assertIn("$SHELL(0x2081)\\a.txt", out)
        self.assertIn("$LANG(2)", out)

    def test_strings_option_prints_the_table(self):
        code, out, err = self.run_tool(installer(header([(DELETE, "one"), (DELETE, "two")]), "solid"), "--strings")
        self.assertEqual(code, 0, err)
        section = out[out.index("[Strings]"):]
        self.assertIn("1\tone", section)
        self.assertIn("5\ttwo", section)

    def test_control_characters_are_escaped(self):
        out = self.result([(DELETE, "red\x1b[31m.txt")])
        self.assertNotIn("\x1b", out)
        self.assertIn("\\u001b[31m", out)


class Failures(ToolCase):
    def test_not_an_installer(self):
        code, out, err = self.run_tool(b"MZ" + bytes(4096))
        self.assertEqual(code, 2)
        self.assertIn("no NSIS header", err)

    def test_ansi_installer_is_refused(self):
        code, out, err = self.run_tool(installer(header(ACTIONS, ansi=True), "stored"))
        self.assertEqual(code, 2)
        self.assertIn("ANSI", err)

    def test_corrupt_stream_is_refused(self):
        data = bytearray(installer(header(ACTIONS), "solid"))
        data[-40:] = bytes(40)
        code, out, err = self.run_tool(bytes(data))
        self.assertEqual(code, 2)
        self.assertIn("nsis-script:", err)

    def test_absurd_header_size_is_refused(self):
        data = bytearray(installer(header(ACTIONS), "stored"))
        position = data.index(MAGIC) + len(MAGIC)
        struct.pack_into("<I", data, position, 1 << 31)
        code, out, err = self.run_tool(bytes(data))
        self.assertEqual(code, 2)
        self.assertIn("makes no sense", err)

    def test_entries_past_the_end_are_refused(self):
        block = bytearray(header(ACTIONS))
        struct.pack_into("<I", block, 4 + 2 * 8 + 4, 1 << 24)
        code, out, err = self.run_tool(installer(bytes(block), "stored"))
        self.assertEqual(code, 2)
        self.assertIn("past the end", err)


if __name__ == "__main__":
    unittest.main()
