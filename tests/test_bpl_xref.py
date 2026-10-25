"""Tests for bin/bpl-xref against small 32-bit PE files built here.

Each fixture is a Delphi-like image assembled byte by byte: code with string and
record references, an import thunk, AnsiString literals, VMTs with published
methods and fields, form and string table resources, exports and a relocation
table. Run with `python3 -m unittest discover -s tests`. Needs pefile.
"""
import os
import struct
import subprocess
import sys
import tempfile
import unittest

try:
    import pefile  # noqa: F401  (bpl-xref needs it, the fixtures don't)
except ImportError:
    raise unittest.SkipTest("bpl-xref needs the pefile module")

BPL_XREF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "bpl-xref")

IMAGE_BASE = 0x400000
TEXT_RVA, DATA_RVA, RSRC_RVA, RELOC_RVA = 0x1000, 0x2000, 0x3000, 0x4000
RT_STRING, RT_RCDATA = 6, 10

# Code layout, as offsets in .text. Every function starts with push ebp; mov ebp, esp.
F_POST, F_SAVE, F_SHOW, F_CANCEL, THUNK = 0x10, 0x40, 0x60, 0x80, 0xC0
VA_POST, VA_SAVE, VA_SHOW, VA_CANCEL = (IMAGE_BASE + TEXT_RVA + f for f in (F_POST, F_SAVE, F_SHOW, F_CANCEL))
# Post loads the literal with mov edx at +3 and the record with mov eax at +8, each imm32 one byte later.
REF_LITERAL, REF_RECORD = VA_POST + 4, VA_POST + 9

LITERAL = "Pedido – cancelado"     # the dash is 0x96 in cp1252, a control character in latin-1
BAD_LITERAL = b"a\x81b"                  # 0x81 is undefined in cp1252
CAPTION = "Edição – pedido"
FIRST_STRING_ID = 65520                  # string table block 4096 holds IDs 65520 to 65535


class Section:
    def __init__(self, rva):
        self.rva = rva
        self.buf = bytearray()
        self.relocs = []

    @property
    def va(self):
        return IMAGE_BASE + self.rva + len(self.buf)

    def align(self, n=4, fill=b"\0"):
        self.buf += fill * (-len(self.buf) % n)

    def pad_to(self, off):
        self.buf += b"\xcc" * (off - len(self.buf))

    def put(self, raw):
        va = self.va
        self.buf += raw
        return va

    def u16(self, value):
        return self.put(struct.pack("<H", value))

    def u32(self, value):
        return self.put(struct.pack("<I", value))

    def ptr(self, va):
        """Write an absolute address, relocated unless it is zero."""
        if va:
            self.relocs.append(self.rva + len(self.buf))
        return self.u32(va)


def short_string(text):
    raw = text.encode("cp1252")
    return bytes([len(raw)]) + raw


def ansi_literal(data, raw):
    """Write a Delphi AnsiString literal (refcount -1, length, text, NUL) and return its text address."""
    data.align()
    data.u32(0xFFFFFFFF)
    data.u32(len(raw))
    return data.put(raw + b"\0")


def imports(data, dll, names):
    """Write an import table for one DLL and return (directory rva, size, {name: IAT slot address})."""
    hints = []
    for name in names:
        data.align(2)
        hints.append(data.va - IMAGE_BASE)
        data.put(b"\0\0" + name.encode() + b"\0")
    dll_rva = data.put(dll.encode() + b"\0") - IMAGE_BASE
    data.align()
    lookup = data.va - IMAGE_BASE
    for h in hints + [0]:
        data.u32(h)
    iat = data.va
    slots = {}
    for name, h in zip(names, hints):
        slots[name] = data.u32(h)
    data.u32(0)
    desc = data.va - IMAGE_BASE
    data.put(struct.pack("<5I", lookup, 0, 0, dll_rva, iat - IMAGE_BASE))
    data.put(b"\0" * 20)
    return desc, 40, slots


def vmt(data, name, parent_cell=0, methods=(), fields=(), field_types=()):
    """Write a Delphi 7 VMT and its tables. Returns (VMT address, class cell).

    The class cell is the vmtSelfPtr slot, which holds the VMT address, the way
    Delphi refers to a class defined in the same module.
    """
    name_va = data.put(short_string(name))
    method_table = field_table = 0
    if methods:
        method_table = data.u16(len(methods))
        for method, code in methods:
            data.u16(2 + 4 + 1 + len(method))
            data.ptr(code)
            data.put(short_string(method))
    if fields:
        class_table = data.u16(len(field_types))
        for cell in field_types:
            data.ptr(cell)
        field_table = data.u16(len(fields))
        data.ptr(class_table)
        for offset, index, field in fields:
            data.u32(offset)
            data.u16(index)
            data.put(short_string(field))
    data.align()
    cell = data.va
    address = cell + 0x4C
    slots = [0] * 19
    slots[0], slots[5], slots[6], slots[8], slots[9], slots[10] = (
        address, field_table, method_table, name_va, 0x3B0, parent_cell)
    for value in slots:
        data.ptr(value)
    data.u32(0)
    return address, cell


def exports(data, dll, symbols):
    """Write an export directory for {name: address} and return (rva, size)."""
    names = sorted(symbols)
    name_rvas = [data.put(n.encode() + b"\0") - IMAGE_BASE for n in names]
    dll_rva = data.put(dll.encode() + b"\0") - IMAGE_BASE
    data.align()
    functions = data.va - IMAGE_BASE
    for n in names:
        data.u32(symbols[n] - IMAGE_BASE)
    name_table = data.va - IMAGE_BASE
    for r in name_rvas:
        data.u32(r)
    ordinals = data.va - IMAGE_BASE
    for i in range(len(names)):
        data.u16(i)
    data.align()
    start = data.va - IMAGE_BASE
    data.put(struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_rva, 1, len(names), len(names),
                         functions, name_table, ordinals))
    return start, 40


def dfm_object(cls, name, props=(), children=()):
    return short_string(cls) + short_string(name) + b"".join(props) + b"\0" + b"".join(children) + b"\0"


def dfm_string(name, text):
    return short_string(name) + b"\x06" + short_string(text)


def dfm_ident(name, ident):
    return short_string(name) + b"\x07" + short_string(ident)


def dfm_int(name, value):
    return short_string(name) + b"\x03" + struct.pack("<h", value)


def dfm_collection(name, items):
    """A collection property whose items are lists of properties."""
    return short_string(name) + b"\x0e" + b"".join(b"\x01" + b"".join(i) + b"\0" for i in items) + b"\0"


def string_block(texts):
    """One string table resource, 16 length-prefixed UTF-16 strings with the unused ones empty."""
    texts = list(texts) + [""] * (16 - len(texts))
    return b"".join(struct.pack("<H", len(t)) + t.encode("utf-16-le") for t in texts)


def resources(tree):
    """Build a .rsrc section for {type id: {name or id: bytes}}, one language each."""
    def ordered(entries):
        named = sorted((k for k in entries if isinstance(k, str)), key=str.upper)
        return named + sorted(k for k in entries if isinstance(k, int))

    types = sorted(tree)
    off = 16 + 8 * len(types)
    type_off, lang_off, entry_off, name_off, blob_off = {}, {}, {}, {}, {}
    for t in types:
        type_off[t] = off
        off += 16 + 8 * len(tree[t])
    keys = [(t, k) for t in types for k in ordered(tree[t])]
    for key in keys:
        lang_off[key] = off
        off += 24
    for key in keys:
        entry_off[key] = off
        off += 16
    for t, k in keys:
        if isinstance(k, str):
            name_off[(t, k)] = off
            off += 2 + 2 * len(k)
    off += -off % 4
    for t, k in keys:
        blob_off[(t, k)] = off
        off += len(tree[t][k]) + (-len(tree[t][k]) % 4)

    out = bytearray(off)

    def directory(at, entries):
        """Entries are (name field, target). The high bit marks a name string or a subdirectory."""
        named = sum(1 for name, _ in entries if name & 0x80000000)
        struct.pack_into("<IIHHHH", out, at, 0, 0, 0, 0, named, len(entries) - named)
        for i, (name, target) in enumerate(entries):
            struct.pack_into("<II", out, at + 16 + 8 * i, name, target)

    directory(0, [(t, 0x80000000 | type_off[t]) for t in types])
    for t in types:
        directory(type_off[t], [((0x80000000 | name_off[(t, k)]) if isinstance(k, str) else k,
                                 0x80000000 | lang_off[(t, k)]) for k in ordered(tree[t])])
    for t, k in keys:
        directory(lang_off[(t, k)], [(0x416, entry_off[(t, k)])])
        blob = tree[t][k]
        struct.pack_into("<IIII", out, entry_off[(t, k)], RSRC_RVA + blob_off[(t, k)], len(blob), 0, 0)
        out[blob_off[(t, k)]:blob_off[(t, k)] + len(blob)] = blob
        if isinstance(k, str):
            raw = struct.pack("<H", len(k)) + k.encode("utf-16-le")
            out[name_off[(t, k)]:name_off[(t, k)] + len(raw)] = raw
    return bytes(out)


def relocations(rvas):
    out = bytearray()
    pages = {}
    for rva in sorted(rvas):
        pages.setdefault(rva & ~0xFFF, []).append(rva & 0xFFF)
    for page, offsets in sorted(pages.items()):
        entries = [(3 << 12) | o for o in offsets]
        if len(entries) % 2:
            entries.append(0)
        out += struct.pack("<II", page, 8 + 2 * len(entries)) + struct.pack(f"<{len(entries)}H", *entries)
    return bytes(out)


def write_pe(path, sections, dirs, dll):
    """Write a PE32 file from [(name, rva, bytes, characteristics)] and {directory index: (rva, size)}."""
    file_align, sect_align, headers = 0x200, 0x1000, 0x400
    raw_off, table = headers, []
    for name, rva, body, chars in sections:
        raw_size = len(body) + (-len(body) % file_align)
        table.append((name, rva, body, chars, raw_off, raw_size))
        raw_off += raw_size
    last = sections[-1]
    size_of_image = last[1] + len(last[2]) + (-len(last[2]) % sect_align)
    data_dirs = b"".join(struct.pack("<II", *dirs.get(i, (0, 0))) for i in range(16))
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 2, 25, len(sections[0][2]), 0, 0, TEXT_RVA, TEXT_RVA, DATA_RVA, IMAGE_BASE,
        sect_align, file_align, 4, 0, 0, 0, 4, 0, 0, size_of_image, headers, 0, 2, 0,
        0x100000, 0x4000, 0x100000, 0x1000, 0, 16) + data_dirs
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, len(optional),
                       0x2102 if dll else 0x0102)
    header = bytearray(headers)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    pos = 0x80
    for chunk in (b"PE\0\0", coff, optional):
        header[pos:pos + len(chunk)] = chunk
        pos += len(chunk)
    for name, rva, body, chars, off, raw_size in table:
        header[pos:pos + 40] = struct.pack("<8sIIIIIIHHI", name, len(body), rva, raw_size, off,
                                           0, 0, 0, 0, chars)
        pos += 40
    with open(path, "wb") as fh:
        fh.write(header)
        for _name, _rva, body, _chars, _off, raw_size in table:
            fh.write(body + b"\0" * (raw_size - len(body)))


def build(path, with_exports, with_relocs):
    """Write a fixture and return the addresses the tests check."""
    data = Section(DATA_RVA)
    module_var = data.u32(0)
    literal = ansi_literal(data, LITERAL.encode("cp1252"))
    bad_literal = ansi_literal(data, BAD_LITERAL)
    data.align()
    data.ptr(bad_literal)
    data.align()
    record = data.ptr(module_var)
    data.u32(FIRST_STRING_ID)
    unused_record = data.ptr(module_var)
    data.u32(FIRST_STRING_ID + 1)
    import_dir = imports(data, "vcl70.bpl", ["@Forms@TForm@", "@Stdctrls@TButton@",
                                             "@Dialogs@ShowMessage$qqrx17System@AnsiString"])
    slots = import_dir[2]
    helper, helper_cell = vmt(data, "THelper")
    base, base_cell = vmt(data, "TFBaseEdit", slots["@Forms@TForm@"], methods=[("FormShow", VA_SHOW)])
    edit, _ = vmt(data, "TFOrderEdit", base_cell,
                  methods=[("BtnSaveClick", VA_SAVE), ("BtnCancelClick", VA_CANCEL)],
                  fields=[(0x3A4, 0, "BtnSave"), (0x3A8, 1, "Helper")],
                  field_types=[slots["@Stdctrls@TButton@"], helper_cell])
    dirs = {1: import_dir[:2]}
    if with_exports:
        # BtnCancelClick stays unexported so the BPL resolves it through the VMT.
        dirs[0] = exports(data, "orders.bpl", {
            "@Uorders@TOrder@Post$qqrv": VA_POST,
            "@Uorders@TFOrderEdit@BtnSaveClick$qqrp14System@TObject": VA_SAVE,
            "@Uorders@TFBaseEdit@FormShow$qqrp14System@TObject": VA_SHOW,
            "@Uorders@SInvalidOrder": record,
            "@Uorders@TFOrderEdit@": edit,
        })

    text = Section(TEXT_RVA)
    text.pad_to(F_POST)
    text.put(b"\x55\x8b\xec\xba")
    text.ptr(literal)
    text.put(b"\xb8")
    text.ptr(record)
    text.put(b"\xe8" + struct.pack("<i", THUNK - (F_POST + 18)))
    text.put(b"\x5d\xc3")
    for off in (F_SAVE, F_SHOW, F_CANCEL):
        text.pad_to(off)
        text.put(b"\x55\x8b\xec\x5d\xc3")
    text.pad_to(THUNK)
    text.put(b"\xff\x25")
    text.ptr(slots["@Dialogs@ShowMessage$qqrx17System@AnsiString"])

    form = b"TPF0" + dfm_object("TFOrderEdit", "FOrderEdit", [
        dfm_int("Left", 8),
        dfm_int("Width", 320),
        dfm_string("Caption", CAPTION),
        dfm_ident("OnShow", "FormShow"),
        dfm_ident("OnClose", "FormClose"),
        dfm_collection("Columns", [[dfm_string("Title", "Customer"), dfm_int("Width", 50)]]),
    ], [
        dfm_object("TButton", "BtnSave", [dfm_int("Top", 200), dfm_ident("OnClick", "BtnSaveClick")]),
        dfm_object("TButton", "BtnCancel", [dfm_ident("OnClick", "BtnCancelClick")]),
    ])
    ghost = b"TPF0" + dfm_object("TFGhost", "FGhost", [dfm_ident("OnClick", "GhostClick")])
    rsrc = resources({
        RT_STRING: {4096: string_block(["Invalid order %s", "Order saved"])},
        RT_RCDATA: {"TFORDEREDIT": form, "TFGHOST": ghost},
    })
    dirs[2] = (RSRC_RVA, len(rsrc))

    sections = [(b".text", TEXT_RVA, bytes(text.buf), 0x60000020),
                (b".data", DATA_RVA, bytes(data.buf), 0xC0000040),
                (b".rsrc", RSRC_RVA, rsrc, 0x40000040)]
    if with_relocs:
        reloc = relocations(text.relocs + data.relocs)
        sections.append((b".reloc", RELOC_RVA, reloc, 0x42000040))
        dirs[5] = (RELOC_RVA, len(reloc))
    write_pe(path, sections, dirs, dll=with_exports)
    return {"literal": literal, "record": record, "unused_record": unused_record,
            "helper": helper, "base": base, "edit": edit}


def run(*args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, BPL_XREF, *args], capture_output=True, env=env, timeout=60)
    # Windows writes text-mode output with CRLF.
    return (r.returncode, r.stdout.decode("utf-8").replace("\r\n", "\n"),
            r.stderr.decode("utf-8").replace("\r\n", "\n"))


class Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bpl = os.path.join(cls.tmp.name, "orders.bpl")
        cls.exe = os.path.join(cls.tmp.name, "orders.exe")
        cls.bare = os.path.join(cls.tmp.name, "norelocs.exe")
        cls.at = build(cls.bpl, with_exports=True, with_relocs=True)
        build(cls.exe, with_exports=False, with_relocs=True)
        build(cls.bare, with_exports=False, with_relocs=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def ok(self, *args):
        code, out, err = run(*args)
        self.assertEqual(code, 0, err)
        return out


class StrTest(Fixtures):
    def test_cp1252_literal_and_its_reference(self):
        out = self.ok("str", self.bpl, LITERAL)
        self.assertIn(f"{LITERAL!r} (cp1252, AnsiString literal) at 0x{self.at['literal']:08x}", out)
        self.assertIn(f"    ref 0x{REF_LITERAL:08x}", out)
        self.assertIn(f"nearest prologue 0x{VA_POST:08x}", out)
        self.assertIn("prev export 0x%08x @Uorders@TOrder@Post$qqrv" % VA_POST, out)

    def test_literal_reference_without_relocations(self):
        out = self.ok("str", self.bare, LITERAL)
        self.assertIn(f"    ref 0x{REF_LITERAL:08x}", out)

    def test_resourcestring_record_and_code(self):
        out = self.ok("str", self.bpl, "Invalid order")
        self.assertIn(f"'Invalid order' (resourcestring {FIRST_STRING_ID}) in 'Invalid order %s'", out)
        self.assertIn(f"    record 0x{self.at['record']:08x} @Uorders@SInvalidOrder", out)
        self.assertIn(f"    ref 0x{REF_RECORD:08x}", out)
        # The raw UTF-16 text inside the string table is not reported on its own.
        self.assertNotIn("utf-16-le", out)

    def test_resourcestring_without_references(self):
        for path in (self.exe, self.bare):
            out = self.ok("str", path, "Order saved")
            self.assertIn(f"(resourcestring {FIRST_STRING_ID + 1})", out)
            self.assertIn(f"    record 0x{self.at['unused_record']:08x}\n    no references", out)

    def test_resourcestring_without_relocations(self):
        out = self.ok("str", self.bare, "Invalid order %s")
        self.assertIn(f"    record 0x{self.at['record']:08x}", out)
        self.assertIn(f"    ref 0x{REF_RECORD:08x}", out)

    def test_no_match(self):
        code, _, err = run("str", self.bpl, "Nothing like this")
        self.assertEqual(code, 1)
        self.assertIn("no match", err)


class FlagsTest(Fixtures):
    def test_thunk_and_cp1252_literal(self):
        out = self.ok("flags", self.bpl)
        self.assertIn(f"f+ thunk.Dialogs_ShowMessage_qqrx17System_AnsiString 6 @ 0x{IMAGE_BASE + TEXT_RVA + THUNK:08x}", out)
        self.assertIn(f"f+ str.Pedido___cancelado 18 @ 0x{self.at['literal']:08x}", out)

    def test_undefined_cp1252_byte_rejects_the_literal(self):
        self.assertNotIn("str.a_b", self.ok("flags", self.bpl))


class StringsTest(Fixtures):
    def test_literals_and_resourcestrings_sorted(self):
        lines = self.ok("strings", self.bpl).splitlines()
        self.assertEqual(lines, [
            f"ansi\t{LITERAL!r}",
            "resourcestring\t-\t'Order saved'",
            "resourcestring\t@Uorders@SInvalidOrder\t'Invalid order %s'",
        ])

    def test_records_without_exports(self):
        lines = self.ok("strings", self.exe).splitlines()
        self.assertIn("resourcestring\t-\t'Invalid order %s'", lines)
        self.assertIn(f"ansi\t{LITERAL!r}", lines)


class DfmTest(Fixtures):
    def test_list(self):
        out = self.ok("dfm", self.bpl)
        self.assertRegex(out, r"TFORDEREDIT  FOrderEdit: TFOrderEdit  \d+ bytes  4 events")
        self.assertRegex(out, r"TFGHOST  FGhost: TFGhost  \d+ bytes  1 events")

    def test_text_keeps_cp1252_caption(self):
        out = self.ok("dfm", self.bpl, "TFORDEREDIT")
        self.assertIn("object FOrderEdit: TFOrderEdit", out)
        self.assertIn(f"  Caption = '{CAPTION}'", out)
        self.assertIn("  object BtnSave: TButton", out)

    def test_all_forms_as_text(self):
        out = self.ok("dfm", "--all", self.bpl)
        self.assertIn("object FOrderEdit: TFOrderEdit\n  Left = 8\n  Width = 320\n", out)
        self.assertIn("      Width = 50\n", out)
        self.assertIn("object FGhost: TFGhost", out)

    def test_no_geometry(self):
        out = self.ok("dfm", "--all", "--no-geometry", self.bpl)
        for prop in ("Left =", "Top =", "Width ="):
            self.assertNotIn(prop, out)
        self.assertIn(f"  Caption = '{CAPTION}'", out)
        self.assertIn("      Title = 'Customer'", out)
        self.assertIn("    OnClick = BtnSaveClick", out)

    def test_events_in_a_package(self):
        out = self.ok("dfm", "--events", self.bpl)
        self.assertIn("TFORDEREDIT  BtnSave.OnClick = BtnSaveClick\n"
                      f"    0x{VA_SAVE:08x} @Uorders@TFOrderEdit@BtnSaveClick$qqrp14System@TObject", out)
        self.assertIn("TFORDEREDIT  BtnCancel.OnClick = BtnCancelClick\n"
                      f"    0x{VA_CANCEL:08x} TFOrderEdit.BtnCancelClick (published)", out)
        self.assertIn("TFORDEREDIT  FOrderEdit.OnShow = FormShow\n"
                      f"    0x{VA_SHOW:08x} TFBaseEdit.FormShow (published)", out)

    def test_events_without_exports(self):
        for path in (self.exe, self.bare):
            out = self.ok("dfm", "--events", path)
            self.assertIn(f"    0x{VA_SAVE:08x} TFOrderEdit.BtnSaveClick (published)", out)
            self.assertIn(f"    0x{VA_SHOW:08x} TFBaseEdit.FormShow (published)", out)

    def test_handler_of_an_imported_ancestor(self):
        out = self.ok("dfm", "--events", self.exe)
        self.assertIn("FOrderEdit.OnClose = FormClose\n    not in this file, TFBaseEdit inherits from "
                      "@Forms@TForm@ in vcl70.bpl, look for the method in its exports", out)

    def test_form_without_a_class(self):
        out = self.ok("dfm", "--events", self.exe)
        self.assertIn("FGhost.OnClick = GhostClick\n    no method with that name and no VMT for TFGhost", out)


class VmtTest(Fixtures):
    def test_list(self):
        for path in (self.bpl, self.bare):
            out = self.ok("vmt", path)
            self.assertIn(f"0x{self.at['helper']:08x} THelper < -  0 methods  0 fields", out)
            self.assertIn(f"0x{self.at['base']:08x} TFBaseEdit < TForm  1 methods  0 fields", out)
            self.assertIn(f"0x{self.at['edit']:08x} TFOrderEdit < TFBaseEdit  2 methods  2 fields", out)

    def test_class_with_methods_fields_and_ancestors(self):
        out = self.ok("vmt", self.exe, "tforderedit")
        self.assertIn(f"0x{self.at['edit']:08x} TFOrderEdit < TFBaseEdit < @Forms@TForm@ in vcl70.bpl", out)
        self.assertIn(f"  TFOrderEdit\n    0x{VA_SAVE:08x} BtnSaveClick\n    0x{VA_CANCEL:08x} BtnCancelClick\n"
                      "    +0x3a4 BtnSave: TButton\n    +0x3a8 Helper: THelper", out)
        self.assertIn(f"  TFBaseEdit\n    0x{VA_SHOW:08x} FormShow", out)

    def test_unknown_class(self):
        code, _, err = run("vmt", self.exe, "TNope")
        self.assertEqual(code, 1)
        self.assertIn("no class with that name", err)


if __name__ == "__main__":
    unittest.main()
