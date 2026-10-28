package com.breachpath.storage;

import com.breachpath.model.Asset;
import com.breachpath.model.Link;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Loads the CSV / text data files. Lines starting with '#' and blank lines are ignored. */
public final class DataLoader {
    private DataLoader() {
    }

    public static Topology loadTopology(Path assetsCsv, Path edgesCsv) throws IOException {
        List<Asset> assets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String[] f : readCsv(assetsCsv, 3, 5)) {
            if (f.length == 4) {
                throw new IllegalArgumentException(assetsCsv.getFileName() + ": asset " + f[0]
                        + " needs 3 columns, or 5 with internetFacing and patched");
            }
            if (!seen.add(f[0])) {
                throw new IllegalArgumentException("Duplicate asset: " + f[0]);
            }
            boolean internetFacing = f.length == 5 && flag(f[3], "internetFacing", f[0]);
            boolean patched = f.length != 5 || flag(f[4], "patched", f[0]);
            assets.add(new Asset(f[0], f[1], Integer.parseInt(f[2]), internetFacing, patched));
        }
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < assets.size(); i++) {
            idx.put(assets.get(i).name(), i);
        }
        List<Link> links = new ArrayList<>();
        for (String[] f : readCsv(edgesCsv, 4)) {
            Integer a = idx.get(f[0]);
            Integer b = idx.get(f[1]);
            if (a == null || b == null) {
                throw new IllegalArgumentException("Unknown asset in edge: " + String.join(",", f));
            }
            links.add(new Link(a, b, Integer.parseInt(f[2]), Boolean.parseBoolean(f[3])));
        }
        return new Topology(assets, links);
    }

    public static List<SecurityEvent> loadEvents(Path eventsCsv) throws IOException {
        List<SecurityEvent> events = new ArrayList<>();
        for (String[] f : readCsv(eventsCsv, 6)) {
            events.add(new SecurityEvent(
                    Integer.parseInt(f[0]), f[1], f[2], Integer.parseInt(f[3]),
                    dash(f[4]), dash(f[5])));
        }
        return events;
    }

    /** Reads a plain text file, skipping blank lines and '#' comments. */
    public static List<String> loadLines(Path file) throws IOException {
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) {
                out.add(t);
            }
        }
        return out;
    }

    /** Accepts true/false, yes/no, y/n and 1/0 in any case. */
    private static boolean flag(String text, String column, String asset) {
        switch (text.toLowerCase(java.util.Locale.ROOT)) {
            case "true":
            case "yes":
            case "y":
            case "1":
                return true;
            case "false":
            case "no":
            case "n":
            case "0":
                return false;
            default:
                throw new IllegalArgumentException("Asset " + asset + ": " + column
                        + " must be true or false but was '" + text + "'");
        }
    }

    private static String dash(String s) {
        return s.equals("-") ? "" : s;
    }

    /** Reads a CSV with a header row; every data row must have exactly {@code columns} fields. */
    private static List<String[]> readCsv(Path path, int columns) throws IOException {
        return readCsv(path, columns, columns);
    }

    /** Like {@link #readCsv(Path, int)} but accepts anywhere from minColumns to maxColumns fields per row. */
    private static List<String[]> readCsv(Path path, int minColumns, int maxColumns) throws IOException {
        List<String[]> rows = new ArrayList<>();
        List<String> lines = Files.readAllLines(path);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(",", -1);
            if (parts.length < minColumns || parts.length > maxColumns) {
                throw new IllegalArgumentException(path.getFileName() + " line " + (i + 1)
                        + ": expected " + (minColumns == maxColumns ? String.valueOf(minColumns)
                        : minColumns + " to " + maxColumns) + " columns but found " + parts.length);
            }
            for (int j = 0; j < parts.length; j++) {
                parts[j] = parts[j].trim();
            }
            rows.add(parts);
        }
        return rows;
    }
}
