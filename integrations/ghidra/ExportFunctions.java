// @category NYRA.FWLab
// Export function metadata. Never executes code from imported firmware.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.io.BufferedWriter;

public class ExportFunctions extends HeadlessScript {
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
        if (analysisTimeoutOccurred()) throw new IllegalStateException("Headless analysis timed out");
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output JSON path");
        try (BufferedWriter out = Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            out.write("{\"schema_version\":1,\"functions\":[");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            boolean first = true;
            int count = 0;
            while (it.hasNext() && !monitor.isCancelled() && count < 20000) {
                Function f = it.next();
                if (!first) out.write(',');
                first = false;
                out.write("{\"name\":" + quote(f.getName()) + ",\"entry\":" + quote(f.getEntryPoint().toString())
                    + ",\"size\":" + f.getBody().getNumAddresses() + ",\"external\":" + f.isExternal() + "}");
                count++;
            }
            out.write("],\"exported\":" + count + "}");
        }
    }
}
