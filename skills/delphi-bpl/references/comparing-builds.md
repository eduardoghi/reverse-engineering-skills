# Comparing two builds

Read this when you need to know what changed between two versions of the same package or EXE.


Export names stay the same between builds of a package and addresses don't. Match exported
functions by name, and nested procedures through the literals they reference (`bpl-xref str` on
both files). Then compare only the instructions the question depends on. A function that was
rewritten may also have been renamed or split, so when an export disappears, look for the same
literals in the new file before concluding the code is gone.

To see everything that changed between two builds, run ghidriff as described in the `binary-diff`
skill. On a BPL it matches most functions by their export names. Filter the JSON by unit
(`test("@Unitname@")`) to find what changed in the area you care about. The exported RTTI
(`@$xp$...`) and VMTs (`@Unit@TClass@`) come out as functions that fail to decompile or decompile
to nonsense, and many of them land in `modified`. Skip names that start with `@$xp$`.

ghidriff misses most changes in texts and forms of a Delphi binary, such as literals with accented
characters, messages used only in except blocks, resourcestrings and every form property. Compare
those with `bpl-xref strings` and `bpl-xref dfm --all --no-geometry`, as the `binary-diff` skill
shows. On an EXE, which has no exports, also name the published methods in the project with
`bpl-xref vmt --names` and `ghidra_scripts/ApplyNames.java` before trusting the report, or changed
event handlers can be missing from it.

For a first pass over one unit, before running ghidriff, compare its exported functions instruction by
instruction. Take each export of the unit and the next export as the range, so the nested procedures
that sit before the next export are included. Disassemble both builds with `objdump`, mask what moves
between builds, and compare the lists. It takes seconds for a few hundred functions.

```python
import re, subprocess
def body(path, start, end):
    out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                          f'--start-address={start}', f'--stop-address={end}', path],
                         capture_output=True, text=True).stdout
    ins = [l.split('\t', 1)[1] for l in out.splitlines() if re.match(r'\s*[0-9a-f]+:\t', l)]
    ins = [re.sub(r'0x[0-9a-f]{5,}', 'ADDR', i) for i in ins]          # absolute addresses
    ins = [re.sub(r'([+-])0x[0-9a-f]+\]', r'\1OFF]', i) for i in ins]  # field offsets
    return [re.sub(r'^(call|j\w+)\s+[0-9a-f]+\b.*', r'\1 X', i) for i in ins]
```

- Check that the lists are not empty before trusting an "equal". `objdump` prints 8 digit addresses
  without leading spaces, and a pattern that required them matched nothing, so every function came
  out "equal" between two builds that had in fact changed.
- When a class gains fields, every method that touches the fields after the new ones changes its
  offsets, so almost the whole unit shows up as different with the same function sizes. Masking the
  displacements removes most of that. What is left at the same size is usually small constants that
  also moved with the layout. Read the diff of the functions the question depends on before calling
  the change a logic change, and use ghidriff when you need the full picture.
