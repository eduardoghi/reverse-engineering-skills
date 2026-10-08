---
name: java-decompile
description: Decompile Java JAR and .class files to readable source with Vineflower, using CFR as a second opinion and javap bytecode as the tie-breaker. Use when you need to know how methods in a JAR are implemented, compare two versions of a JAR, or find SQL, URLs and constants inside Java code. Prefer it over javap alone for anything beyond signatures.
---

# Java decompilation

Decompiled code is a reconstruction, not the original source. Local variable names, loop shapes and
`if`/`else` order may differ from what was written, and some methods come out wrong. Treat it as a strong
lead and confirm anything important in the bytecode.

Tools: `java-decompile` (wraps Vineflower, from this repo's `bin/`), `cfr`, and `javap`/`jar` from the JDK.
Run `java-decompile --check` if any of them seems to be missing.

## Method

1. **Look at the layout first.**

   ```sh
   jar tf app.jar | sed 's#/[^/]*$##' | sort | uniq -c | sort -rn | head -30
   ```

   Find the vendor's own packages and note whether they sit at the root, under `BOOT-INF/classes/`
   (Spring Boot) or under `WEB-INF/classes/` (WAR). Nested JARs under `BOOT-INF/lib/` or `WEB-INF/lib/` are
   separate inputs: extract the one you need and decompile it on its own.
   `META-INF/maven/*/*/pom.properties` gives the product version and the bundled libraries.

2. **Check for real source.** A `*-sources.jar` next to the binary, a public repository for the version in
   `pom.properties`, or source files inside the JAR beat any decompiler. Use them when they exist.

3. **Decompile with Vineflower**, limited to the vendor package. `--only` takes the slash-separated class
   name (`com/vendor/product`), without any `BOOT-INF/classes/` prefix:

   ```sh
   java-decompile --only=com/vendor/product app.jar /tmp/app-src
   ```

   Vineflower still copies every non-class resource in the JAR (`.properties`, `.xml`, `.txt`) into the
   output. Only the `.java` files under the prefix are decompiled.

4. **Get a second opinion from CFR** when a method looks wrong: missing bodies, `<unknown>` types, tangled
   control flow, or a comment saying it couldn't be decompiled. `--jarfilter` is a regex over dotted class
   names:

   ```sh
   cfr app.jar --outputdir /tmp/app-src-cfr --jarfilter '^com\.vendor\.product\.Foo$'
   ```

5. **Confirm in the bytecode** when a conclusion depends on a branch, a constant, the exact method called
   or the order of operations, and always when Vineflower and CFR disagree:

   ```sh
   javap -c -p -v -cp app.jar com.vendor.product.Foo
   ```

   For classes under `BOOT-INF/classes/`, extract them first (`unzip app.jar 'BOOT-INF/classes/*' -d /tmp/x`)
   and use `-cp /tmp/x/BOOT-INF/classes`. The bytecode decides.

`javap -p` alone is fine for a quick look at signatures and `javap -v` for the constant pool. Don't stop
there when you need to know what a method does.

## java-decompile behaviour

- Without an output directory it creates a new `${TMPDIR:-/tmp}/<jar name>-src.XXXXXX` with `mktemp`
  and prints the final path. Read the path from the output instead of guessing it.
- Every output directory gets a `.java-decompile-output` marker file.
- A non-empty output directory is refused. `--clean` empties it (keeping the directory) only if it has
  the marker. A folder that java-decompile didn't create is never cleaned; delete it by hand if you
  really want to reuse it.
- Never reuse an output directory for a different input, since files from the earlier run would look
  like part of the new one.
- An output path that is a symlink, a regular file or a directory owned by another user is refused, and
  so are `/`, `$HOME` and the current directory.
- If `--only` fails or finds nothing in a JAR (Vineflower 1.12.0 crashes with `NoSuchFileException` on
  classes under `BOOT-INF/classes/`), it extracts the matching classes from the root, `BOOT-INF/classes/`
  and `WEB-INF/classes/` into a temporary directory and decompiles them from there. The output paths
  are the same as a direct run.
- Extra Vineflower options go after `--`, e.g. `java-decompile app.jar out -- --thread-count=4`. The
  script passes them before `--only`, because Vineflower 1.12.0 treats anything after `--only=` as an
  input path and ignores it with `warn: missing '...'`. Keep that order if you call Vineflower directly.
- A full decompile of a 15 MB fat JAR takes minutes. Use `--only` whenever you know the package.

## Comparing two versions of a JAR

1. Use separate, new output directories for each version. Never decompile the second version into the
   first one's directory.
2. Compare the class lists before decompiling anything:

   ```sh
   jar tf old.jar | grep '\.class$' | sort > old.txt
   jar tf new.jar | grep '\.class$' | sort > new.txt
   diff old.txt new.txt
   ```

3. Find the classes that changed by hashing the `.class` files (unzip both, then `sha256sum` per file and
   join on the path). Bytecode can change with the same source when the compiler or build changes, so a
   different hash means "look at it", not "the logic changed".
4. Check `META-INF/maven/*/*/pom.properties` in both for version bumps of the product and its libraries.
5. Decompile only the changed vendor classes, with the same tool and options on both sides, and
   `diff -ru old-src new-src`.
6. Ignore differences that are only formatting, renamed local variables (`var1` vs `var2`), or reordered
   synthetic members (`lambda$foo$3`, `access$000`, bridge methods). Their names and numbering shift when
   unrelated code moves.
7. For quick triage, `javap -p` signatures and the string constants from `javap -v` often show the change
   (new SQL, new endpoint, new parameter name) before you read any method.
8. Confirm each change you report in the bytecode of both versions.

Keep decompiled output out of git repositories.
