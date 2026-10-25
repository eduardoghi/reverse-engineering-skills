// Name functions from a file of "0xADDRESS Name" lines, such as the output of
// `bpl-xref vmt --names`. A function that Ghidra doesn't have yet is created,
// because in Delphi executables the handlers reached only through a published
// method table are often missing after auto-analysis.
//
// analyzeHeadless PROJECT_DIR PROJECT -process PROGRAM -scriptPath ghidra_scripts \
//     -preScript ApplyNames.java names.txt
//
// As a pre-script the names are in place before analysis runs, so analysis
// also follows the calls inside the new functions.
//@category Delphi

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ApplyNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            printerr("usage: ApplyNames.java NAMES_FILE");
            return;
        }
        int renamed = 0, created = 0, failed = 0;
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] parts = line.trim().split("\\s+", 2);
            if (parts.length < 2) {
                continue;
            }
            try {
                var address = toAddr(Long.decode(parts[0]));
                Function function = getFunctionAt(address);
                if (function == null) {
                    if (createFunction(address, parts[1]) == null) {
                        failed++;
                    } else {
                        created++;
                    }
                } else {
                    function.setName(parts[1], SourceType.USER_DEFINED);
                    renamed++;
                }
            } catch (Exception e) {
                printerr("ApplyNames: " + line.trim() + ": " + e.getMessage());
                failed++;
            }
        }
        println("ApplyNames: renamed " + renamed + ", created " + created + ", failed " + failed);
    }
}
