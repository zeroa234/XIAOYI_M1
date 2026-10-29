// Exact address-set coverage of the unchanged main Ghidra project.
// Uses Ghidra AddressSet and Listing; no function creation or disassembly.
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.io.PrintWriter;

public class AuditM1Coverage extends GhidraScript {
    private String hex(Address a) { return a.toString(); }
    private void ranges(Path path, AddressSetView set) throws Exception {
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(path))) {
            w.println("start\tend\tbytes");
            for (AddressRange r : set.getAddressRanges())
                w.println(hex(r.getMinAddress()) + "\t" + hex(r.getMaxAddress()) + "\t" + r.getLength());
        }
    }
    public void run() throws Exception {
        Path out = Path.of(getScriptArgs()[0]);
        Files.createDirectories(out);
        var block = currentProgram.getMemory().getBlock(toAddr(0x2000));
        if (block == null || !block.getName().startsWith(".text")) throw new IllegalStateException("Missing text block");
        AddressSet text = new AddressSet(block.getStart(), block.getEnd());
        AddressSet bodies = new AddressSet(), instructions = new AddressSet(), data = new AddressSet();
        long functionCount = 0, bodySum = 0, instructionCount = 0, orphanCount = 0, indirectCalls = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!text.contains(f.getEntryPoint())) continue;
            AddressSetView body = f.getBody().intersect(text);
            bodies.add(body);
            bodySum += body.getNumAddresses();
            functionCount++;
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("orphan-instructions.tsv")));
             PrintWriter calls = new PrintWriter(Files.newBufferedWriter(out.resolve("unresolved-calls.tsv")))) {
            w.println("address\tbytes\tassembly");
            calls.println("callsite\ttarget\tkind");
            for (Instruction ins : currentProgram.getListing().getInstructions(text, true)) {
                instructions.add(ins.getMinAddress(), ins.getMaxAddress());
                instructionCount++;
                if (currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress()) == null) {
                    w.println(hex(ins.getAddress()) + "\t" + ins.getLength() + "\t" + ins.toString());
                    orphanCount++;
                }
                if (ins.getFlowType().isCall()) {
                    Address[] flows = ins.getFlows();
                    if (flows.length == 0) {
                        calls.println(hex(ins.getAddress()) + "\t\tindirect");
                        indirectCalls++;
                    }
                    for (Address dest : flows)
                        if (currentProgram.getFunctionManager().getFunctionAt(dest) == null)
                            calls.println(hex(ins.getAddress()) + "\t" + hex(dest) + "\tno-exact-function-entry");
                }
            }
        }
        for (Data d : currentProgram.getListing().getDefinedData(text, true)) data.add(d.getMinAddress(), d.getMaxAddress());
        AddressSet orphanBytes = instructions.subtract(bodies);
        AddressSet undefined = text.subtract(instructions.union(data));
        ranges(out.resolve("function-body-union.tsv"), bodies);
        ranges(out.resolve("orphan-instruction-ranges.tsv"), orphanBytes);
        ranges(out.resolve("undefined-ranges.tsv"), undefined);
        String summary = "{\n" +
            "  \"qualification\": \"Exact Ghidra listing/address-set inventory, not proof of semantic code coverage\",\n" +
            "  \"functions\": " + functionCount + ",\n" +
            "  \"textBytes\": " + text.getNumAddresses() + ",\n" +
            "  \"sumFunctionBodyBytesInText\": " + bodySum + ",\n" +
            "  \"uniqueFunctionBodyBytesInText\": " + bodies.getNumAddresses() + ",\n" +
            "  \"instructions\": " + instructionCount + ",\n" +
            "  \"instructionBytes\": " + instructions.getNumAddresses() + ",\n" +
            "  \"definedDataBytes\": " + data.getNumAddresses() + ",\n" +
            "  \"instructionDataOverlapBytes\": " + instructions.intersect(data).getNumAddresses() + ",\n" +
            "  \"undefinedBytes\": " + undefined.getNumAddresses() + ",\n" +
            "  \"orphanInstructions\": " + orphanCount + ",\n" +
            "  \"orphanInstructionBytes\": " + orphanBytes.getNumAddresses() + ",\n" +
            "  \"indirectCallsites\": " + indirectCalls + "\n}\n";
        Files.writeString(out.resolve("summary.json"), summary);
        println(summary);
    }
}
