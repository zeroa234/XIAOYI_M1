// Read-only catalog and decompiler export for the embedded sub-CPU payload.
// This intentionally does NOT apply the main program's 27 outline helpers.
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.io.*;
import java.util.*;

public class ExportEmbeddedSubcpu extends GhidraScript {
    private static final long[] VECTOR_SLOTS = {0x20, 0x24, 0x28, 0x2c, 0x30, 0x38, 0x3c};
    private static class Str {
        long address; String text; TreeSet<Long> users = new TreeSet<>();
        Str(long a, String t) { address = a; text = t; }
    }
    private static class Row {
        Function f; int instructions;
        TreeSet<Long> callers = new TreeSet<>(), callees = new TreeSet<>();
        TreeSet<Long> strings = new TreeSet<>(), ram = new TreeSet<>(), mmio = new TreeSet<>();
        TreeSet<Long> image = new TreeSet<>();
        Row(Function f) { this.f = f; }
    }
    private final TreeMap<Long, Str> strings = new TreeMap<>();
    private final TreeMap<Long, Row> rows = new TreeMap<>();
    private final TreeMap<Long, TreeSet<Long>> missing = new TreeMap<>();
    private MemoryBlock payload;
    private long base, size;
    private long thumbBitCalls = 0;

    private String hex(long n) { return String.format("%08x", n); }
    private String esc(String s) {
        return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n");
    }
    private String addresses(Collection<Long> values, int limit) {
        ArrayList<String> out = new ArrayList<>(); int n = 0;
        for (long v : values) { if (limit > 0 && n++ >= limit) break; out.add(hex(v)); }
        return String.join(";", out);
    }
    private boolean printable(int c) { return c >= 32 && c <= 126 || c == 9 || c == 10 || c == 13; }

    private void scanStrings() throws Exception {
        byte[] bytes = new byte[Math.toIntExact(payload.getSize())];
        payload.getBytes(payload.getStart(), bytes);
        int start = 0;
        for (int i = 0; i < bytes.length; i++) {
            int c = bytes[i] & 255;
            if (printable(c)) continue;
            if (c == 0 && i > start) {
                long address = payload.getStart().getOffset() + start;
                strings.put(address, new Str(address,
                    new String(bytes, start, i - start, StandardCharsets.US_ASCII)));
            }
            start = i + 1;
        }
    }

    // Direct reference, literal-pool pointer and up to two pointer levels.
    // The payload is one raw block; every pointer that lands inside it is image-local.
    private void reference(Row row, long value, int depth, Map<Long, Integer> seen) {
        value &= 0xffffffffL;
        if (seen.getOrDefault(value, -1) >= depth) return;
        seen.put(value, depth);
        if (value >= base && value < base + size) row.image.add(value);
        if (value >= 0xc0000000L && value < 0xd0000000L) row.ram.add(value);
        if (value >= 0x20000000L && value < 0x40000000L) row.mmio.add(value);
        Map.Entry<Long, Str> candidate = strings.floorEntry(value);
        if (candidate != null && value < candidate.getKey() + candidate.getValue().text.length()) {
            row.strings.add(candidate.getKey());
            candidate.getValue().users.add(row.f.getEntryPoint().getOffset());
            if (candidate.getKey() + candidate.getValue().text.length() - value >= 4) return;
        }
        if (depth <= 0 || (value & 3) != 0) return;
        try {
            Address a = toAddr(value);
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b != null && b.isInitialized() && b == payload) {
                reference(row, Integer.toUnsignedLong(currentProgram.getMemory().getInt(a)), depth - 1, seen);
            }
        } catch (Exception ignored) { /* end of block or unmapped */ }
    }
    private Long constant(Varnode node, Map<String, Long> values) {
        if (node.isConstant()) return Long.valueOf(node.getOffset());
        return values.get(node.toString());
    }
    private void pcodeReferences(Row row, Instruction ins, Map<Long, Integer> seen) {
        Map<String, Long> values = new HashMap<>();
        for (PcodeOp op : ins.getPcode()) {
            for (Varnode input : op.getInputs()) if (input.isConstant() && input.getSize() == 4)
                reference(row, input.getOffset(), 0, seen);
            Long a = op.getNumInputs() > 0 ? constant(op.getInput(0), values) : null;
            Long b = op.getNumInputs() > 1 ? constant(op.getInput(1), values) : null;
            Long result = null;
            switch (op.getOpcode()) {
                case PcodeOp.COPY: case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT: result = a; break;
                case PcodeOp.INT_ADD: if (a != null && b != null) result = a + b; break;
                case PcodeOp.INT_SUB: if (a != null && b != null) result = a - b; break;
                case PcodeOp.INT_AND: if (a != null && b != null) result = a & b; break;
                case PcodeOp.INT_OR: if (a != null && b != null) result = a | b; break;
                case PcodeOp.INT_LEFT: if (a != null && b != null) result = a << (b & 63); break;
                case PcodeOp.LOAD:
                    if (b != null) {
                        reference(row, b, 2, seen);
                        try {
                            if (op.getOutput().getSize() == 4)
                                result = Integer.toUnsignedLong(currentProgram.getMemory().getInt(toAddr(b & 0xffffffffL)));
                        } catch (Exception ignored) {}
                    }
                    break;
                default: break;
            }
            if (op.getOutput() != null) {
                values.remove(op.getOutput().toString());
                if (result != null) {
                    result &= 0xffffffffL;
                    values.put(op.getOutput().toString(), result);
                    reference(row, result, op.getOpcode() == PcodeOp.LOAD ? 1 : 0, seen);
                }
            }
        }
    }
    private void catalog() throws Exception {
        FunctionIterator fs = currentProgram.getFunctionManager().getFunctions(true);
        while (fs.hasNext()) {
            Function f = fs.next();
            if (payload.contains(f.getEntryPoint())) rows.put(f.getEntryPoint().getOffset(), new Row(f));
        }
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            new AddressSet(payload.getStart(), payload.getEnd()), true);
        long n = 0;
        while (instructions.hasNext()) {
            if (++n % 10000 == 0) monitor.checkCancelled();
            Instruction ins = instructions.next();
            Function f = getFunctionContaining(ins.getAddress());
            Row row = f == null ? null : rows.get(f.getEntryPoint().getOffset());
            if (row != null) {
                row.instructions++;
                Map<Long, Integer> seen = new HashMap<>();
                for (Reference ref : ins.getReferencesFrom())
                    if (ref.getToAddress().isMemoryAddress() && !ref.getReferenceType().isFlow())
                        reference(row, ref.getToAddress().getOffset(), 2, seen);
                pcodeReferences(row, ins, seen);
            }
            if (ins.getFlowType().isCall()) {
                for (Address target : ins.getFlows()) {
                    long raw = target.getOffset();
                    long t = raw & ~1L; // BLX to Thumb stores the low bit in the pointer.
                    if ((raw & 1L) != 0) thumbBitCalls++;
                    if (!payload.contains(toAddr(t))) continue;
                    if (row != null) row.callees.add(t);
                    Row callee = rows.get(t);
                    if (callee != null && row != null) callee.callers.add(f.getEntryPoint().getOffset());
                    if (getFunctionAt(toAddr(t)) == null && getFunctionContaining(toAddr(t)) == null)
                        missing.computeIfAbsent(t, k -> new TreeSet<>()).add(ins.getAddress().getOffset());
                }
            }
        }
    }
    private String stringRefs(Row row, int limit) {
        ArrayList<String> refs = new ArrayList<>(); int n = 0;
        for (long a : row.strings) { if (n++ >= limit) break; refs.add(hex(a) + ":" + strings.get(a).text); }
        return esc(String.join(" | ", refs));
    }
    private String disassembly(Function f) {
        StringBuilder out = new StringBuilder();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) { Instruction i = it.next(); out.append("// ").append(i.getAddress()).append("  ").append(i).append('\n'); }
        return out.toString();
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) throw new IllegalArgumentException("output base size [timeout] [limit]");
        Path out = Path.of(args[0]);
        base = Long.decode(args[1]);
        size = Long.decode(args[2]);
        int timeout = args.length > 3 ? Integer.parseInt(args[3]) : 30;
        int limit = args.length > 4 ? Integer.parseInt(args[4]) : 0;
        if (timeout < 1 || timeout > 300) throw new IllegalArgumentException("timeout out of range");
        if (limit < 0) throw new IllegalArgumentException("limit must be non-negative");
        payload = currentProgram.getMemory().getBlock(toAddr(base));
        if (payload == null) throw new IllegalStateException("payload block not found");
        if (payload.getStart().getOffset() != base || payload.getSize() != size)
            throw new IllegalStateException("payload block geometry mismatch");
        Files.createDirectories(out.resolve("decompiled"));
        long start = System.nanoTime();
        scanStrings();
        catalog();
        println("CATALOG functions=" + rows.size() + " strings=" + strings.size() + " missing=" + missing.size());

        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("functions.tsv"), StandardCharsets.UTF_8))) {
            w.println("entry\tend\tbody_bytes\tinstruction_count\tcaller_count\tcallee_count\tcallers\tcallees\tstrings\tram_globals\tmmio\tpayload_refs\tstring_count\tram_count\tmmio_count\tpayload_count\tname\tstring_addresses");
            for (Row r : rows.values()) w.println(hex(r.f.getEntryPoint().getOffset()) + "\t" +
                hex(r.f.getBody().getMaxAddress().getOffset()) + "\t" + r.f.getBody().getNumAddresses() + "\t" +
                r.instructions + "\t" + r.callers.size() + "\t" + r.callees.size() + "\t" +
                addresses(r.callers,20) + "\t" + addresses(r.callees,0) + "\t" + stringRefs(r,30) + "\t" +
                addresses(r.ram,100) + "\t" + addresses(r.mmio,100) + "\t" + addresses(r.image,100) + "\t" +
                r.strings.size() + "\t" + r.ram.size() + "\t" + r.mmio.size() + "\t" + r.image.size() + "\t" +
                esc(r.f.getName()) + "\t" + addresses(r.strings,30));
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("strings.tsv"), StandardCharsets.UTF_8))) {
            w.println("address\tlength\ttext\tfunctions");
            for (Str s : strings.values()) w.println(hex(s.address) + "\t" + s.text.length() + "\t" + esc(s.text) + "\t" + addresses(s.users,0));
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("unrecognized-call-targets.tsv"), StandardCharsets.UTF_8))) {
            w.println("target\tcallsite_count\tcallsites\tcontaining_function\tstatus");
            for (Map.Entry<Long, TreeSet<Long>> e : missing.entrySet()) {
                Function f = getFunctionContaining(toAddr(e.getKey()));
                w.println(hex(e.getKey()) + "\t" + e.getValue().size() + "\t" + addresses(e.getValue(),0) + "\t" +
                    (f == null ? "" : hex(f.getEntryPoint().getOffset())) + "\t未创建函数");
            }
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("vectors.tsv"), StandardCharsets.UTF_8))) {
            w.println("slot\tword\ttarget\tfunction");
            for (long slot : VECTOR_SLOTS) {
                Address a = toAddr(base + slot);
                long target = Integer.toUnsignedLong(currentProgram.getMemory().getInt(a));
                Function f = getFunctionAt(toAddr(target));
                if (f == null) f = getFunctionContaining(toAddr(target));
                w.println(hex(base + slot) + "\t" + hex(target) + "\t" + hex(target) + "\t" +
                    (f == null ? "" : hex(f.getEntryPoint().getOffset())));
            }
        }
        double catalogSeconds = (System.nanoTime() - start) / 1e9;
        DecompInterface decompiler = new DecompInterface();
        int ok = 0, failed = 0; long cBytes = 0;
        try (PrintWriter failures = new PrintWriter(Files.newBufferedWriter(out.resolve("failures.tsv"), StandardCharsets.UTF_8));
             PrintWriter timings = new PrintWriter(Files.newBufferedWriter(out.resolve("decompile-timings.tsv"), StandardCharsets.UTF_8))) {
            failures.println("entry\tseconds\treason\tfallback");
            timings.println("entry\tseconds\tstatus\tc_bytes");
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            for (Row r : rows.values()) {
                if (limit != 0 && ok + failed >= limit) break;
                monitor.checkCancelled();
                long t = System.nanoTime(); String c = null, error = "";
                try {
                    DecompileResults result = decompiler.decompileFunction(r.f, timeout, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null)
                        c = result.getDecompiledFunction().getC();
                    else error = result.getErrorMessage();
                } catch (Exception e) { error = e.toString(); }
                double seconds = (System.nanoTime() - t) / 1e9;
                String entry = hex(r.f.getEntryPoint().getOffset());
                String content = "/* Embedded sub-CPU candidate static analysis; no main-program outline helpers applied. */\n";
                if (c != null) { ok++; content += c; }
                else {
                    failed++;
                    content += "/* 反编译失败，以下为反汇编替代。 */\n// " + esc(error) + "\n" + disassembly(r.f);
                    failures.println(entry + "\t" + seconds + "\t" + esc(error) + "\tdecompiled/" + entry + ".c");
                    failures.flush();
                }
                Path file = out.resolve("decompiled").resolve(entry + ".c");
                Files.writeString(file, content, StandardCharsets.UTF_8);
                long bytes = Files.size(file); cBytes += bytes;
                timings.println(entry + "\t" + seconds + "\t" + (c != null ? "成功" : "失败") + "\t" + bytes);
                timings.flush();
                if ((ok + failed) % 100 == 0) println("PROGRESS " + (ok + failed) + "/" + rows.size() + " success=" + ok + " failed=" + failed);
            }
        } finally { decompiler.dispose(); }
        double elapsed = (System.nanoTime() - start) / 1e9;
        String summary = "{\n" +
            "  \"payload_base\": \"" + hex(base) + "\",\n" +
            "  \"payload_size\": " + size + ",\n" +
            "  \"functions\": " + rows.size() + ",\n" +
            "  \"strings\": " + strings.size() + ",\n" +
            "  \"unrecognized_call_targets\": " + missing.size() + ",\n" +
            "  \"thumb_bit_call_targets\": " + thumbBitCalls + ", " +
            "  \"success\": " + ok + ",\n" +
            "  \"failed\": " + failed + ",\n" +
            "  \"c_bytes\": " + cBytes + ",\n" +
            "  \"catalog_seconds\": " + catalogSeconds + ",\n" +
            "  \"elapsed_seconds\": " + elapsed + ",\n" +
            "  \"decompile_timeout_seconds\": " + timeout + ",\n" +
            "  \"limit\": " + limit + ",\n" +
            "  \"outline_helpers_applied\": false\n" +
            "}\n";
        Files.writeString(out.resolve("summary.json"), summary, StandardCharsets.UTF_8);
        println("COMPLETE functions=" + rows.size() + " success=" + ok + " failed=" + failed + " seconds=" + elapsed);
    }
}
