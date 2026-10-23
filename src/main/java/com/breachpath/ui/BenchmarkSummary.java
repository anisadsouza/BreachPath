package com.breachpath.ui;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Turns the text printed by {@code Benchmarks.runAll()} into a five-row summary (one row per
 * required concept). No JavaFX here, so it is unit-tested.
 */
public final class BenchmarkSummary {

    /** One concept: did its correctness check pass, and how did it perform? */
    public record Row(String concept, boolean passed, String check, String performance, String workload) {
    }

    private static final Pattern TITLE = Pattern.compile("^==\\s*(.*?)\\s*==\\s*$");
    private static final Pattern WORKLOAD = Pattern.compile("\\(([^()]*)\\)\\s*$");
    private static final Pattern FLOW_CHECK = Pattern.compile("(\\d+) random graphs checked, mismatches: (\\d+)");
    private static final Pattern FLOW_ROW = Pattern.compile(
            "^(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+([\\d.]+)\\s*$", Pattern.MULTILINE);
    private static final Pattern TRIE = Pattern.compile(
            "trie:\\s*([\\d.]+) ms\\s+linear scan:\\s*([\\d.]+) ms\\s+results match:\\s*(\\w+)");
    private static final Pattern WILDCARD = Pattern.compile(
            "dictionary:\\s*([\\d.]+) ms\\s+naive scan:\\s*([\\d.]+) ms\\s+results match:\\s*(\\w+)");
    private static final Pattern SEGMENT = Pattern.compile(
            "segment tree:\\s*([\\d.]+) ms\\s+naive scan:\\s*([\\d.]+) ms\\s+results match:\\s*(\\w+)");
    private static final Pattern RB_TIME = Pattern.compile(
            "insert:\\s*([\\d.]+) ms\\s+remove:\\s*([\\d.]+) ms\\s+height after insert:\\s*(\\d+)\\s*\\(log2 n = ([\\d.]+)\\)");
    private static final Pattern RB_OK = Pattern.compile(
            "invariants hold after insert:\\s*(\\w+),\\s*after remove:\\s*(\\w+),\\s*matches TreeMap:\\s*(\\w+)");

    private BenchmarkSummary() {
    }

    public static List<Row> parse(String output) {
        Map<String, String> sections = sections(output == null ? "" : output);
        List<Row> rows = new ArrayList<>();
        rows.add(flowRow(sections));
        rows.add(scanRow("Prefix trie", "Same results as a linear scan", sections, "Prefix Trie", TRIE, "linear scan"));
        rows.add(scanRow("Wildcard dictionary", "Same matches as a naive scan", sections, "Wildcard dictionary",
                WILDCARD, "naive scan"));
        rows.add(scanRow("Segment tree", "Same answers as a naive scan", sections, "Segment tree", SEGMENT,
                "naive scan"));
        rows.add(redBlackRow(sections));
        return rows;
    }

    // ---- rows -------------------------------------------------------------------------------

    private static Row flowRow(Map<String, String> sections) {
        String check = find(sections, "Edmonds-Karp vs brute-force");
        String table = find(sections, "Max flow:");
        Matcher c = FLOW_CHECK.matcher(check);
        if (!c.find()) {
            return missing("Max flow / min cut");
        }
        int trials = Integer.parseInt(c.group(1));
        int mismatches = Integer.parseInt(c.group(2));
        boolean passed = mismatches == 0;
        String checkText = passed
                ? "Max flow and min cut match a brute-force check on " + trials + " random graphs"
                : mismatches + " of " + trials + " random graphs disagree with the brute-force check";

        String perf = "";
        Matcher r = FLOW_ROW.matcher(table);
        String last = null;
        while (r.find()) {
            last = String.format(Locale.ROOT, "Edmonds-Karp: %s nodes, %s edges in %s ms",
                    r.group(1), grouped(r.group(2)), r.group(4));
        }
        if (last != null) {
            perf = last;
        }
        return new Row("Max flow / min cut", passed, checkText, perf, "largest generated graph");
    }

    private static Row scanRow(String concept, String passText, Map<String, String> sections, String key,
                               Pattern p, String baseline) {
        String body = find(sections, key);
        Matcher m = p.matcher(body);
        if (!m.find()) {
            return missing(concept);
        }
        double fast = Double.parseDouble(m.group(1));
        double slow = Double.parseDouble(m.group(2));
        boolean passed = Boolean.parseBoolean(m.group(3));
        String perf = String.format(Locale.ROOT, "%.1f ms vs %.1f ms for a %s (%.0f\u00d7 faster)",
                fast, slow, baseline, slow / Math.max(fast, 0.001));
        return new Row(concept, passed, passed ? passText : "Results differ from the " + baseline,
                perf, workload(sections, key));
    }

    private static Row redBlackRow(Map<String, String> sections) {
        String body = find(sections, "Red-black tree");
        Matcher ok = RB_OK.matcher(body);
        Matcher time = RB_TIME.matcher(body);
        if (!ok.find() || !time.find()) {
            return missing("Red-black tree");
        }
        boolean passed = Boolean.parseBoolean(ok.group(1)) && Boolean.parseBoolean(ok.group(2))
                && Boolean.parseBoolean(ok.group(3));
        double total = Double.parseDouble(time.group(1)) + Double.parseDouble(time.group(2));
        String perf = String.format(Locale.ROOT, "%.1f ms for all inserts and removals, height %s (log2 n = %s)",
                total, time.group(3), time.group(4));
        return new Row("Red-black tree", passed,
                passed ? "Invariants hold after inserts and removals, and contents match TreeMap"
                        : "An invariant or the TreeMap comparison failed",
                perf, workload(sections, "Red-black tree"));
    }

    // ---- helpers ----------------------------------------------------------------------------

    private static Row missing(String concept) {
        return new Row(concept, false, "No result found in the benchmark output", "", "");
    }

    private static Map<String, String> sections(String output) {
        Map<String, String> map = new LinkedHashMap<>();
        String title = null;
        StringBuilder body = new StringBuilder();
        for (String line : output.split("\\R")) {
            Matcher t = TITLE.matcher(line);
            if (t.matches()) {
                if (title != null) {
                    map.put(title, body.toString());
                }
                title = t.group(1);
                body = new StringBuilder();
            } else if (title != null) {
                body.append(line).append('\n');
            }
        }
        if (title != null) {
            map.put(title, body.toString());
        }
        return map;
    }

    private static String find(Map<String, String> sections, String titleStart) {
        for (Map.Entry<String, String> e : sections.entrySet()) {
            if (e.getKey().startsWith(titleStart)) {
                return e.getValue();
            }
        }
        return "";
    }

    private static String workload(Map<String, String> sections, String titleStart) {
        for (String title : sections.keySet()) {
            if (title.startsWith(titleStart)) {
                Matcher m = WORKLOAD.matcher(title);
                return m.find() ? m.group(1) : "";
            }
        }
        return "";
    }

    private static String grouped(String digits) {
        return String.format(Locale.ROOT, "%,d", Long.parseLong(digits));
    }
}
