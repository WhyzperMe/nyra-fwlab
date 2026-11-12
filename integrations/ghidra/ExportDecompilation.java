// @category NYRA.FWLab
// Bounded decompilation of lens-related functions; inferred pseudocode only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.io.BufferedWriter;
import java.util.Locale;

public class ExportDecompilation extends GhidraScript {
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output JSON path");
        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler program");
        int count = 0;
        boolean first = true;
        try (BufferedWriter out = Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            out.write("{\"schema_version\":1,\"kind\":\"inferred_pseudocode\",\"functions\":[");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled() && count < 120) {
                Function f = it.next();
                String name = f.getName().toLowerCase(Locale.ROOT);
                if (!(name.contains("zoom") || name.contains("focus") || name.contains("motor")
                      || name.contains("lens") || name.contains("i2c") || name.contains("ptz"))) continue;
                DecompileResults result = ifc.decompileFunction(f, 12, monitor);
                if (!first) out.write(',');
                first = false;
                String code = result.decompileCompleted() && result.getDecompiledFunction() != null
                    ? result.getDecompiledFunction().getC() : "";
                if (code.length() > 300000) code = code.substring(0, 300000);
                out.write("{\"name\":" + quote(f.getName()) + ",\"entry\":" + quote(f.getEntryPoint().toString())
                    + ",\"decompiled\":" + result.decompileCompleted() + ",\"pseudocode\":" + quote(code) + "}");
                count++;
            }
            out.write("],\"exported\":" + count + ",\"limited_to_lens_functions\":true}");
        } finally {
            ifc.dispose();
        }
    }
}
