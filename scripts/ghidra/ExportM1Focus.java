// Export existing Ghidra decompiler results and reference types; no patching.
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Arrays;

public class ExportM1Focus extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean existingOnly = Arrays.asList(args).contains("existing-only");
        boolean rootsOnly = Arrays.asList(args).contains("roots-only");
        Path destination = Path.of(args[0]);
        Files.createDirectories(destination);
        // Remove only an earlier analysis label that was placed inside a block.
        Function stale = getFunctionAt(toAddr(0x35fa68));
        if (stale != null && stale.getName().equals("candidate_35fa68"))
            currentProgram.getFunctionManager().removeFunction(stale.getEntryPoint());
        // These instruction-verified outline helpers change caller registers/SP/flags.
        // Treating them as ordinary ABI calls hides their effects in the C view.
        try (PrintWriter note = new PrintWriter(Files.newBufferedWriter(destination.resolve("inline-helpers.txt")))) {
            for (long[] spec : new long[][] {{0xf6c58,12}, {0x32ed84,12}, {0x395da8,12},
                    {0x384d60,16}, {0x156af4,12}, {0x156a70,16},
                    {0x156990,20}, {0x1569a4,20}, {0x1569c8,28},
                    {0x3fb948,12}, {0x3223f4,12}, {0x36005c,12}, {0x11ba10,12},
                    {0x32240c,12}, {0x3564ac,12}, {0x3bfe18,12}, {0x3d6074,20},
                    {0x354a8c,12}, {0x354ab0,12}, {0x354abc,16},
                    {0x11b034,12}, {0x3fe4d0,12}, {0x361134,12},
                    {0x3dcfc4,12}, {0x3dcf34,16}, {0x3dcf64,16}, {0x3dcf94,20}}) {
                long entry = spec[0];
                disassemble(toAddr(entry));
                Function helper = getFunctionAt(toAddr(entry));
                if (helper == null) helper = createFunction(toAddr(entry), "outline_" + Long.toHexString(entry));
                if (helper == null || helper.getBody().getNumAddresses() != spec[1])
                    throw new IllegalStateException("Unexpected outline helper body at " + toAddr(entry));
                helper.setInline(true);
                note.println(helper.getEntryPoint() + " inline, verified " + spec[1] + "-byte body");
            }
        }
        LinkedHashSet<Function> functions = new LinkedHashSet<>();
        LinkedHashSet<Function> callers = new LinkedHashSet<>();
        long[] targets = {0x358c7c, 0x358d5c, 0x395c44, 0x3703c4,
            0x39b48c, 0x39b51c, 0x36e0c8, 0x395b0c, 0x371634,
            0x375668, 0x2421dc, 0x359fc4, 0x3d8d9c,
            0x7e788, 0x7e874, 0x87fac, 0x92558, 0x92644,
            0x95d10, 0xa194c, 0xc2a6c, 0xc2bac, 0x10e6e4,
            0x10e6f0, 0x39ba50, 0x39bac4, 0x156754, 0x430b8c};
        if (args.length > 1) {
            targets = Files.readAllLines(Path.of(args[1])).stream()
                .map(String::trim).filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .mapToLong(Long::decode).toArray();
        }
        try (PrintWriter index = new PrintWriter(Files.newBufferedWriter(destination.resolve("references.txt")))) {
            index.println("CANDIDATE STATIC ANALYSIS. Not a camera-verified memory image.");
            index.println("language=" + currentProgram.getLanguageID());
            for (long target : targets) {
                Address address = toAddr(target);
                Function function = getFunctionContaining(address);
                if (function == null && !existingOnly) {
                    disassemble(address);
                    function = createFunction(address, "candidate_" + Long.toHexString(target));
                }
                index.println("TARGET " + address + " FUNCTION " + (function == null ? "NONE" : function.getEntryPoint()));
                if (function != null) functions.add(function);
                for (Reference reference : getReferencesTo(address)) {
                    index.println("  " + reference.getFromAddress() + " " + reference.getReferenceType());
                    if (reference.getReferenceType().isCall()) {
                        Function caller = getFunctionContaining(reference.getFromAddress());
                        if (caller != null) callers.add(caller);
                    }
                }
            }
        }
        // Always export all requested roots before a popular getter's many callers.
        if (!rootsOnly) functions.addAll(callers);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        try {
            int count = 0;
            for (Function function : functions) {
                monitor.checkCancelled();
                if (count++ >= 60) break;
                DecompileResults result = decompiler.decompileFunction(function, 20, monitor);
                Path file = destination.resolve(function.getEntryPoint() + ".c.txt");
                String content = "/* Candidate static analysis; verify against instructions. */\n";
                if (result.decompileCompleted()) content += result.getDecompiledFunction().getC();
                else content += "DECOMPILE FAILED: " + result.getErrorMessage();
                Files.writeString(file, content);
            }
            println("Exported focus functions: " + Math.min(count, 60));
        } finally { decompiler.dispose(); }
    }
}
