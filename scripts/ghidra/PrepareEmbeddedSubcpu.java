// Prepare an isolated embedded ARM image for analysis.
// Only reads the imported payload, verifies the vector table, and seeds functions.
// No firmware bytes are modified and no main-program outline helper is applied.
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class PrepareEmbeddedSubcpu extends GhidraScript {
    private static final long[] VECTOR_SLOTS = {0x20, 0x24, 0x28, 0x2c, 0x30, 0x38, 0x3c};

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("base and payload size required");
        long base = Long.decode(args[0]);
        long size = Long.decode(args[1]);
        Address start = toAddr(base);
        MemoryBlock block = currentProgram.getMemory().getBlock(start);
        if (block == null) throw new IllegalStateException("payload block not found at " + start);
        if (block.getStart().getOffset() != base) throw new IllegalStateException("unexpected block start");
        if (block.getSize() != size) throw new IllegalStateException("unexpected block size " + block.getSize());
        // BinaryLoader with -loader-baseAddr places the block at 0xdfc90000 but
        // may leave the program image base at 0. The block geometry is the
        // authoritative check here; do not relocate the program.
        block.setName("embedded_subcpu");
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(true);
        println("BLOCK " + block.getName() + " base=" + start + " size=" + size);
        println("IMAGE_BASE " + currentProgram.getImageBase());

        int created = 0;
        for (long slot : VECTOR_SLOTS) {
            Address slotAddress = toAddr(base + slot);
            long target = Integer.toUnsignedLong(currentProgram.getMemory().getInt(slotAddress));
            println("VECTOR slot=" + slotAddress + " target=" + toAddr(target));
            if (target < base || target >= base + size || (target & 3) != 0)
                throw new IllegalStateException("vector target outside payload or unaligned: " + toAddr(target));
            Address targetAddress = toAddr(target);
            if (getFunctionAt(targetAddress) == null && getFunctionContaining(targetAddress) == null) {
                disassemble(targetAddress);
                Function f = getFunctionAt(targetAddress);
                if (f == null && getFunctionContaining(targetAddress) == null)
                    f = createFunction(targetAddress, "subcpu_vec_" + Long.toHexString(slot));
                if (f == null) {
                    f = getFunctionAt(targetAddress);
                }
                if (f == null) throw new IllegalStateException("failed to create vector function " + targetAddress);
                created++;
            }
        }
        println("PREPARED vectors=" + VECTOR_SLOTS.length + " created=" + created);
    }
}
