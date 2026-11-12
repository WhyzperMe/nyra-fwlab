// @category NYRA.FWLab
// Export static references to function entries, not a complete dynamic call graph.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.io.BufferedWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.PriorityQueue;

public class ExportCallGraph extends GhidraScript {
    private static final int MAX_EDGES = 30000;
    private static final int MAX_REFERENCES = 1000000;
    private record Call(String caller, String callee, String site) {}
    private static final Comparator<Call> ORDER = Comparator.comparing(Call::site)
        .thenComparing(Call::caller).thenComparing(Call::callee);

    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output JSON path");
        PriorityQueue<Call> edges = new PriorityQueue<>(MAX_EDGES, ORDER.reversed());
        int references = 0;
        int calls = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function dst = it.next();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(dst.getEntryPoint());
            while (refs.hasNext()) {
                if (++references > MAX_REFERENCES) throw new IllegalStateException("Static reference limit exceeded");
                monitor.checkCancelled();
                Reference ref = refs.next();
                if (!ref.getReferenceType().isCall()) continue;
                Function src = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (src == null) continue;
                calls++;
                Call edge = new Call(src.getName(), dst.getName(), ref.getFromAddress().toString());
                if (edges.size() < MAX_EDGES) {
                    edges.add(edge);
                } else if (ORDER.compare(edge, edges.peek()) < 0) {
                    edges.remove();
                    edges.add(edge);
                }
            }
        }
        ArrayList<Call> sorted = new ArrayList<>(edges);
        sorted.sort(ORDER);
        try (BufferedWriter out = Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            out.write("{\"schema_version\":1,\"kind\":\"static_entry_references\",\"edges\":[");
            boolean first = true;
            for (Call edge : sorted) {
                if (!first) out.write(',');
                first = false;
                out.write("{\"caller\":" + quote(edge.caller()) + ",\"callee\":" + quote(edge.callee())
                    + ",\"site\":" + quote(edge.site()) + "}");
            }
            out.write("],\"exported\":" + sorted.size() + ",\"truncated\":" + (calls > MAX_EDGES) + "}");
        }
    }
}
