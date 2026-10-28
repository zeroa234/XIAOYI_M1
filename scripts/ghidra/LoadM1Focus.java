// Map table-declared candidate sections for offline analysis only.
// Reuses Ghidra's loader, memory and disassembly APIs; no firmware is changed.
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class LoadM1Focus extends GhidraScript {
    private void initialized(String name, long address, String file) throws Exception {
        Path path = Path.of(file);
        try (FileInputStream stream = new FileInputStream(path.toFile())) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                name, toAddr(address), stream, Files.size(path), monitor, false);
            block.setRead(true);
            block.setWrite(name.equals(".data"));
            block.setExecute(false);
        }
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("rodata data uninitialized-map.tsv required");
        initialized(".rodata", 0x43f800L, args[0]);
        initialized(".data", 0xc09b0000L, args[1]);
        for (String line : Files.readAllLines(Path.of(args[2]))) {
            String[] fields = line.split("\t");
            MemoryBlock block = currentProgram.getMemory().createUninitializedBlock(
                fields[0], toAddr(Long.decode(fields[1])), Long.decode(fields[2]), false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
        }
        MemoryBlock text = currentProgram.getMemory().getBlock(toAddr(0x2000));
        text.setName(".text.candidate");
        text.setExecute(true);
        text.setWrite(false);
        long[] seeds = {0x358c7c, 0x358d5c, 0x395c44, 0x3703c4,
            0x39b48c, 0x39b51c, 0x36e0c8, 0x395b0c, 0x371634,
            0x375668, 0x2421dc, 0x359fc4, 0x3d8d9c};
        for (long seed : seeds) {
            disassemble(toAddr(seed));
            if (getFunctionAt(toAddr(seed)) == null && getFunctionContaining(toAddr(seed)) == null)
                createFunction(toAddr(seed), "candidate_" + Long.toHexString(seed));
        }
        println("Mapped candidate sections. RAM blocks are uninitialized, not a runtime dump.");
    }
}
