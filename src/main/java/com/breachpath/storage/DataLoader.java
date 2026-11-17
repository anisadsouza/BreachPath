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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Loads the CSV / text data files, either from disk or from text (for uploads through the web API).
 * Lines starting with '#' and blank lines are ignored. Every problem is reported as an
 * {@link IllegalArgumentException} that names the file, line and column, so bad input is rejected
 * instead of silently producing a wrong analysis.
 */
public final class DataLoader {
    /** Largest cost accepted for a host or link (the planner treats 1,000,000 as "never cut"). */
    public static final int MAX_COST = 1_000_000;
    /** Alerts are counted per hour of one day. */
    public static final int HOURS = 24;

    private DataLoader() {
    }

    // ---- topology ---------------------------------------------------------------------------

    public static Topology loadTopology(Path assetsCsv, Path edgesCsv) throws IOException {
        return parseTopology(Files.readAllLines(assetsCsv), Files.readAllLines(edgesCsv),
                assetsCsv.getFileName().toString(), edgesCsv.getFileName().toString());
    }

    /** Parses the assets and links from CSV text (see the README for the columns). */
    public static Topology parseTopology(String assetsText, String edgesText) {
        return parseTopology(splitLines(assetsText), splitLines(edgesText), "assets.csv", "network_edges.csv");
    }

    private static Topology parseTopology(List<String> assetLines, List<String> edgeLines,
                                          String assetsName, String edgesName) {
        List<Asset> assets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Row row : readCsv(assetLines, assetsName, "name", 3, 5)) {
            String[] f = row.fields;
            if (f.length == 4) {
                throw new IllegalArgumentException(row.where() + ": asset " + f[0]
                        + " needs 3 columns, or 5 with internetFacing and patched");
            }
            if (f[0].isEmpty()) {
                throw new IllegalArgumentException(row.where() + ": asset name is empty");
            }
            if (!seen.add(f[0])) {
                throw new IllegalArgumentException("Duplicate asset: " + f[0]);
            }
            boolean internetFacing = f.length == 5 && flag(f[3], "internetFacing", f[0]);
            boolean patched = f.length != 5 || flag(f[4], "patched", f[0]);
            assets.add(new Asset(f[0], f[1], cost(row, 2, "isolationCost"), internetFacing, patched));
        }
        if (assets.isEmpty()) {
            throw new IllegalArgumentException(assetsName + ": no assets found (at least one is required)");
        }
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < assets.size(); i++) {
            idx.put(assets.get(i).name(), i);
        }
        List<Link> links = new ArrayList<>();
        for (Row row : readCsv(edgeLines, edgesName, "from", 4, 4)) {
            String[] f = row.fields;
            Integer a = idx.get(f[0]);
            Integer b = idx.get(f[1]);
            if (a == null || b == null) {
                throw new IllegalArgumentException("Unknown asset in edge: " + String.join(",", f));
            }
            boolean bidirectional = flag(f[3], "bidirectional", f[0] + " to " + f[1]);
            links.add(new Link(a, b, cost(row, 2, "cost"), bidirectional));
        }
        return new Topology(assets, links);
    }

    // ---- events -----------------------------------------------------------------------------

    public static List<SecurityEvent> loadEvents(Path eventsCsv) throws IOException {
        return parseEvents(Files.readAllLines(eventsCsv), eventsCsv.getFileName().toString());
    }

    /** Parses the alert log from CSV text. */
    public static List<SecurityEvent> parseEvents(String text) {
        return parseEvents(splitLines(text), "security_events.csv");
    }

    private static List<SecurityEvent> parseEvents(List<String> lines, String name) {
        List<SecurityEvent> events = new ArrayList<>();
        for (Row row : readCsv(lines, name, "hour", 6, 6)) {
            String[] f = row.fields;
            int hour = integer(row, 0, "hour");
            if (hour < 0 || hour >= HOURS) {
                throw new IllegalArgumentException(row.where() + ": hour must be 0 to " + (HOURS - 1)
                        + " but was " + hour);
            }
            if (f[1].isEmpty()) {
                throw new IllegalArgumentException(row.where() + ": host is empty");
            }
            int count = integer(row, 3, "count");
            if (count < 0) {
                throw new IllegalArgumentException(row.where() + ": count must not be negative but was " + count);
            }
            events.add(new SecurityEvent(hour, f[1], f[2], count, dash(f[4]), dash(f[5])));
        }
        return events;
    }

    // ---- plain text lists -------------------------------------------------------------------

    /** Reads a plain text file, skipping blank lines and '#' comments. */
    public static List<String> loadLines(Path file) throws IOException {
        return parseLines(Files.readAllLines(file));
    }

    /** Splits text into lines, skipping blank lines and '#' comments. */
    public static List<String> parseLines(String text) {
        return parseLines(splitLines(text));
    }

    private static List<String> parseLines(List<String> lines) {
        List<String> out = new ArrayList<>();
        for (String line : lines) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) {
                out.add(t);
            }
        }
        return out;
    }

    // ---- helpers ----------------------------------------------------------------------------

    private static List<String> splitLines(String text) {
        if (text == null || text.isEmpty()) {
            return new ArrayList<>();
        }
        String t = text.startsWith("﻿") ? text.substring(1) : text;
        List<String> out = new ArrayList<>();
        for (String line : t.split("\\R", -1)) {
            out.add(line);
        }
        return out;
    }

    /** Accepts true/false, yes/no, y/n and 1/0 in any case. */
    private static boolean flag(String text, String column, String what) {
        switch (text.toLowerCase(Locale.ROOT)) {
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
                throw new IllegalArgumentException(what + ": " + column
                        + " must be true or false but was '" + text + "'");
        }
    }

    private static String dash(String s) {
        return s.equals("-") ? "" : s;
    }

    private static int cost(Row row, int column, String name) {
        int value = integer(row, column, name);
        if (value < 0 || value > MAX_COST) {
            throw new IllegalArgumentException(row.where() + ": " + name + " must be between 0 and "
                    + MAX_COST + " but was " + value);
        }
        return value;
    }

    private static int integer(Row row, int column, String name) {
        String text = row.fields[column];
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(row.where() + ": " + name + " must be a whole number but was '"
                    + text + "'");
        }
    }

    /** One data row with its position, so errors can say where the problem is. */
    private static final class Row {
        final String file;
        final int line;
        final String[] fields;

        Row(String file, int line, String[] fields) {
            this.file = file;
            this.line = line;
            this.fields = fields;
        }

        String where() {
            return file + " line " + line;
        }
    }

    /**
     * Reads CSV lines: the first line is a header whose first column must be {@code firstHeader}
     * (so a file uploaded without a header is rejected instead of losing its first row); every
     * data row must have between minColumns and maxColumns fields. An empty list gives no rows.
     */
    private static List<Row> readCsv(List<String> lines, String file, String firstHeader,
                                     int minColumns, int maxColumns) {
        List<Row> rows = new ArrayList<>();
        if (lines.isEmpty()) {
            return rows;
        }
        String header = lines.get(0).trim().split(",", -1)[0].trim();
        if (!header.equalsIgnoreCase(firstHeader)) {
            throw new IllegalArgumentException(file + " line 1: expected a header row starting with '"
                    + firstHeader + "' but found '" + header + "'");
        }
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split(",", -1);
            if (parts.length < minColumns || parts.length > maxColumns) {
                throw new IllegalArgumentException(file + " line " + (i + 1)
                        + ": expected " + (minColumns == maxColumns ? String.valueOf(minColumns)
                        : minColumns + " to " + maxColumns) + " columns but found " + parts.length);
            }
            for (int j = 0; j < parts.length; j++) {
                parts[j] = parts[j].trim();
            }
            rows.add(new Row(file, i + 1, parts));
        }
        return rows;
    }
}