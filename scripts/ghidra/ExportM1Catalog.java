// 全量只读目录与反编译导出；调用端必须使用 -readOnly -noanalysis。
// @category M1
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.*;
import java.nio.file.*;
import java.io.*;
import java.util.*;

public class ExportM1Catalog extends GhidraScript {
    private static final long[][] HELPERS = {{0xf6c58,12}, {0x32ed84,12}, {0x395da8,12},
        {0x384d60,16}, {0x156af4,12}, {0x156a70,16}, {0x156990,20}, {0x1569a4,20},
        {0x1569c8,28}, {0x3fb948,12}, {0x3223f4,12}, {0x36005c,12}, {0x11ba10,12},
        {0x32240c,12}, {0x3564ac,12}, {0x3bfe18,12}, {0x3d6074,20}, {0x354a8c,12},
        {0x354ab0,12}, {0x354abc,16}, {0x11b034,12}, {0x3fe4d0,12}, {0x361134,12},
        {0x3dcfc4,12}, {0x3dcf34,16}, {0x3dcf64,16}, {0x3dcf94,20}};
    private static class Str {
        long address; String text; TreeSet<Long> users = new TreeSet<>();
        Str(long a, String t) { address = a; text = t; }
    }
    private static class Row {
        Function f; int instructions;
        TreeSet<Long> callers = new TreeSet<>(), callees = new TreeSet<>();
        TreeSet<Long> strings = new TreeSet<>(), ram = new TreeSet<>(), mmio = new TreeSet<>();
        Row(Function f) { this.f = f; }
    }
    private final TreeMap<Long, Str> strings = new TreeMap<>();
    private final TreeMap<Long, Row> rows = new TreeMap<>();
    private final TreeMap<Long, TreeSet<Long>> missing = new TreeMap<>();
    private MemoryBlock textBlock;
    private String hex(long n) { return String.format("%08x", n); }
    private String esc(String s) {
        return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n");
    }
    private String addresses(Collection<Long> values, int limit) {
        ArrayList<String> out = new ArrayList<>(); int n = 0;
        for (long v : values) { if (n++ >= limit) break; out.add(hex(v)); }
        return String.join(";", out);
    }
    private boolean printable(int c) { return c >= 32 && c <= 126 || c == 9 || c == 10 || c == 13; }
    private void scanStrings() throws Exception {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!(b.getName().equals(".rodata") || b.getName().equals(".data")) || !b.isInitialized()) continue;
            byte[] bytes = new byte[Math.toIntExact(b.getSize())]; b.getBytes(b.getStart(), bytes);
            int start = 0;
            for (int i = 0; i < bytes.length; i++) {
                int c = bytes[i] & 255;
                if (printable(c)) continue;
                if (c == 0 && i > start) strings.put(b.getStart().getOffset() + start,
                    new Str(b.getStart().getOffset() + start,
                        new String(bytes, start, i - start, java.nio.charset.StandardCharsets.US_ASCII)));
                start = i + 1;
            }
        }
    }
    // 直接引用、字面量池及两级指针。循环保护；不会扫描任意内存范围。
    private void reference(Row row, long value, int depth, Map<Long, Integer> seen) {
        value &= 0xffffffffL;
        if (seen.getOrDefault(value, -1) >= depth) return;
        seen.put(value, depth);
        if (value >= 0xc0000000L && value < 0xd0000000L) row.ram.add(value);
        if (value >= 0x20000000L && value < 0x40000000L) row.mmio.add(value);
        Map.Entry<Long, Str> candidate = strings.floorEntry(value);
        if (candidate != null && value < candidate.getKey() + candidate.getValue().text.length()) {
            row.strings.add(candidate.getKey()); candidate.getValue().users.add(row.f.getEntryPoint().getOffset());
            // 32 位指针的低位字节也可能恰好组成 1–3 字节的 ASCII 短串。
            // 保留短串候选，同时继续追踪指针，避免漏掉 .data 指针指向的真实字符串。
            if (candidate.getKey() + candidate.getValue().text.length() - value >= 4) return;
        }
        if (depth <= 0 || (value & 3) != 0) return;
        try {
            Address a = toAddr(value); MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b != null && b.isInitialized() && (b == textBlock || b.getName().equals(".rodata") || b.getName().equals(".data")))
                reference(row, Integer.toUnsignedLong(currentProgram.getMemory().getInt(a)), depth - 1, seen);
        } catch (Exception ignored) { /* 块末尾或未映射地址 */ }
    }
    private Long constant(Varnode node, Map<String, Long> values) {
        if (node.isConstant()) return Long.valueOf(node.getOffset());
        return values.get(node.toString());
    }
    // Ghidra 的 ARM p-code 把 PC 读取替换为当前指令对应的常数；折叠 ADR / ADD rX,pc。
    // 仅在单条指令内传播常量，避免把条件执行或控制流误当成确定的跨指令赋值。
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
                    result &= 0xffffffffL; values.put(op.getOutput().toString(), result);
                    reference(row, result, op.getOpcode() == PcodeOp.LOAD ? 1 : 0, seen);
                }
            }
        }
    }
    private void catalog() throws Exception {
        FunctionIterator fs = currentProgram.getFunctionManager().getFunctions(true);
        while (fs.hasNext()) {
            Function f = fs.next();
            if (textBlock.contains(f.getEntryPoint())) rows.put(f.getEntryPoint().getOffset(), new Row(f));
        }
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            new AddressSet(textBlock.getStart(), textBlock.getEnd()), true);
        long n = 0;
        while (instructions.hasNext()) {
            if (++n % 10000 == 0) monitor.checkCancelled();
            Instruction ins = instructions.next(); Function f = getFunctionContaining(ins.getAddress());
            Row row = f == null ? null : rows.get(f.getEntryPoint().getOffset());
            if (row != null) {
                row.instructions++; Map<Long, Integer> seen = new HashMap<>();
                for (Reference ref : ins.getReferencesFrom())
                    if (ref.getToAddress().isMemoryAddress() && !ref.getReferenceType().isFlow())
                        reference(row, ref.getToAddress().getOffset(), 2, seen);
                pcodeReferences(row, ins, seen);
            }
            if (ins.getFlowType().isCall()) {
                for (Address target : ins.getFlows()) {
                    long t = target.getOffset();
                    if (row != null) row.callees.add(t);
                    Row callee = rows.get(t);
                    if (callee != null && row != null) callee.callers.add(f.getEntryPoint().getOffset());
                    if (textBlock.contains(target) && getFunctionAt(target) == null && ins.getMnemonicString().toUpperCase().startsWith("BL"))
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
        if (args.length < 1) throw new IllegalArgumentException("输出目录 [函数上限，0=全量] [超时秒，30..60] [起始地址]");
        Path out = Path.of(args[0]); int limit = args.length > 1 ? Integer.parseInt(args[1]) : 0;
        int timeout = args.length > 2 ? Integer.parseInt(args[2]) : 45;
        long startAddress = args.length > 3 ? Long.decode(args[3]) : 0;
        if (limit < 0 || timeout < 30 || timeout > 60) throw new IllegalArgumentException("上限/超时参数错误");
        Files.createDirectories(out.resolve("decompiled")); long start = System.nanoTime();
        textBlock = currentProgram.getMemory().getBlock(toAddr(0x2000));
        if (textBlock == null || !textBlock.getName().startsWith(".text")) throw new IllegalStateException("未找到 .text");
        scanStrings(); catalog();
        println("CATALOG functions=" + rows.size() + " strings=" + strings.size() + " missing=" + missing.size());
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("functions.tsv")))) {
            w.println("entry\tend\tbody_bytes\tinstruction_count\tcaller_count\tcallee_count\tcallers\tcallees\tstrings\tram_globals\tmmio\tstring_count\tram_count\tmmio_count\tname\tstring_addresses");
            for (Row r : rows.values()) w.println(hex(r.f.getEntryPoint().getOffset()) + "\t" + hex(r.f.getBody().getMaxAddress().getOffset()) + "\t" +
                r.f.getBody().getNumAddresses() + "\t" + r.instructions + "\t" + r.callers.size() + "\t" + r.callees.size() + "\t" +
                addresses(r.callers,20) + "\t" + addresses(r.callees,Integer.MAX_VALUE) + "\t" + stringRefs(r,30) + "\t" +
                addresses(r.ram,100) + "\t" + addresses(r.mmio,100) + "\t" + r.strings.size() + "\t" + r.ram.size() + "\t" +
                r.mmio.size() + "\t" + esc(r.f.getName()) + "\t" + addresses(r.strings,30));
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("strings.tsv")))) {
            w.println("address\tlength\ttext\tfunctions");
            for (Str s : strings.values()) w.println(hex(s.address) + "\t" + s.text.length() + "\t" + esc(s.text) + "\t" + addresses(s.users,Integer.MAX_VALUE));
        }
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out.resolve("unrecognized-call-targets.tsv")))) {
            w.println("target\tcallsite_count\tcallsites\tcontaining_function\tstatus");
            for (Map.Entry<Long, TreeSet<Long>> e : missing.entrySet()) {
                Function f = getFunctionContaining(toAddr(e.getKey()));
                w.println(hex(e.getKey()) + "\t" + e.getValue().size() + "\t" + addresses(e.getValue(),Integer.MAX_VALUE) + "\t" +
                    (f == null ? "" : hex(f.getEntryPoint().getOffset())) + "\t未创建函数");
            }
        }
        double catalogSeconds = (System.nanoTime() - start) / 1e9;
        int transaction = currentProgram.startTransaction("只读导出：临时 outline helper 内联属性");
        int ok = 0, failed = 0; long cBytes = 0;
        DecompInterface decompiler = new DecompInterface();
        try (PrintWriter helpers = new PrintWriter(Files.newBufferedWriter(out.resolve("inline-helpers.tsv")));
             PrintWriter failures = new PrintWriter(Files.newBufferedWriter(out.resolve("failures.tsv")));
             PrintWriter timings = new PrintWriter(Files.newBufferedWriter(out.resolve("decompile-timings.tsv")))) {
            helpers.println("entry\texpected_body_bytes\tstatus");
            for (long[] spec : HELPERS) {
                Function f = getFunctionAt(toAddr(spec[0]));
                String status = "缺少现有函数，未创建";
                if (f != null && f.getBody().getNumAddresses() == spec[1]) { f.setInline(true); status = "已核验大小，仅内存内联"; }
                else if (f != null) status = "大小不符，保留现状";
                helpers.println(hex(spec[0]) + "\t" + spec[1] + "\t" + status);
            }
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            failures.println("entry\tseconds\treason\tfallback"); timings.println("entry\tseconds\tstatus\tc_bytes");
            for (Row r : rows.tailMap(startAddress).values()) {
                if (limit != 0 && ok + failed >= limit) break;
                monitor.checkCancelled(); long t = System.nanoTime(); String c = null, error = "";
                try {
                    DecompileResults result = decompiler.decompileFunction(r.f, timeout, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) c = result.getDecompiledFunction().getC();
                    else error = result.getErrorMessage();
                } catch (Exception e) { error = e.toString(); }
                double seconds = (System.nanoTime() - t) / 1e9; String entry = hex(r.f.getEntryPoint().getOffset());
                String content = "/* 候选解码静态分析；必须核对指令。outline helper 清单见 inline-helpers.tsv。 */\n";
                if (c != null) { ok++; content += c; }
                else {
                    failed++; content += "/* 反编译失败，以下为反汇编替代。 */\n// " + esc(error) + "\n" + disassembly(r.f);
                    failures.println(entry + "\t" + seconds + "\t" + esc(error) + "\tdecompiled/" + entry + ".c"); failures.flush();
                }
                Path file = out.resolve("decompiled").resolve(entry + ".c"); Files.writeString(file, content);
                long bytes = Files.size(file); cBytes += bytes;
                timings.println(entry + "\t" + seconds + "\t" + (c != null ? "成功" : "失败") + "\t" + bytes); timings.flush();
                if ((ok + failed) % 100 == 0) println("PROGRESS " + (ok + failed) + "/" + rows.size() + " success=" + ok + " failed=" + failed + " seconds=" + ((System.nanoTime()-start)/1e9));
            }
        } finally {
            decompiler.dispose(); currentProgram.endTransaction(transaction, false);
        }
        double elapsed = (System.nanoTime() - start) / 1e9;
        Files.writeString(out.resolve("summary.json"), "{\n  \"functions\": " + rows.size() + ",\n  \"strings\": " + strings.size() +
            ",\n  \"unrecognized_call_targets\": " + missing.size() + ",\n  \"success\": " + ok + ",\n  \"failed\": " + failed +
            ",\n  \"c_bytes\": " + cBytes + ",\n  \"catalog_seconds\": " + catalogSeconds + ",\n  \"elapsed_seconds\": " + elapsed +
            ",\n  \"timeout_seconds\": " + timeout + ",\n  \"limit\": " + limit + "\n}\n");
        println("COMPLETE functions=" + rows.size() + " success=" + ok + " failed=" + failed + " seconds=" + elapsed);
    }
}
