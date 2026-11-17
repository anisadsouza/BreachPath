package com.breachpath.web;

import com.breachpath.engine.AttackPaths;
import com.breachpath.engine.ContainmentPlan;
import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.IocEngine;
import com.breachpath.engine.ScalingBenchmarks;
import com.breachpath.model.Asset;
import com.breachpath.model.Incident;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import com.breachpath.ui.DashboardModel;
import com.breachpath.ui.ReportWriter;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Application service behind the REST API. It owns one {@link DashboardModel} (the same model the
 * JavaFX dashboard uses), validates every request, runs the Java algorithms on the server and
 * returns plain maps and lists that {@link Json} can write. Nothing is precomputed in the browser.
 *
 * <p>All model access is synchronized, so concurrent requests cannot interleave a re-analysis with
 * an incident update. The state is one shared session, which is enough for a single-analyst tool.
 *
 * <p>Failures: invalid input throws {@link IllegalArgumentException} (HTTP 400), a request that needs
 * an analysis before one was run throws {@link IllegalStateException} (HTTP 409).
 */
public final class BreachPathService {
    /** Largest network accepted from an upload. */
    public static final int MAX_ASSETS = 500;
    private static final int MAX_LIST = 100;
    private static final int MAX_DELTA = 100_000;
    private static final String DEFAULT_COMPROMISED = "WS-Alice";
    private static final String DEFAULT_TARGET = "DB-PROD";

    private final Path dataDir;
    private DashboardModel model;
    private String dataSource;

    private final AtomicBoolean benchmarkRunning = new AtomicBoolean();
    private volatile Map<String, Object> lastBenchmark;

    public BreachPathService(Path dataDir) throws IOException {
        this.dataDir = dataDir;
        resetData();
    }

    // ---- data -------------------------------------------------------------------------------

    /** Reloads the sample data from the data directory and runs the default analysis if its hosts exist. */
    public synchronized Map<String, Object> resetData() throws IOException {
        DashboardModel loaded = DashboardModel.load(dataDir);
        checkSize(loaded.topology());
        this.model = loaded;
        this.dataSource = "sample data (" + dataDir + ")";
        tryDefaultAnalysis();
        return health();
    }

    /**
     * Replaces the data with uploaded CSV / text. Everything is parsed and checked first; if any
     * file is invalid the current data stays exactly as it was.
     */
    public synchronized Map<String, Object> replaceData(Map<String, Object> body) {
        String assets = requiredText(body, "assets");
        String edges = requiredText(body, "edges");
        String events = requiredText(body, "events");
        String iocs = optionalText(body, "iocs");
        String patterns = optionalText(body, "patterns");
        DashboardModel loaded = DashboardModel.fromText(assets, edges, events, iocs, patterns);
        checkSize(loaded.topology());
        this.model = loaded;
        this.dataSource = "uploaded data";
        tryDefaultAnalysis();
        return health();
    }

    private void tryDefaultAnalysis() {
        Topology t = model.topology();
        if (t.has(DEFAULT_COMPROMISED) && t.has(DEFAULT_TARGET)) {
            model.analyse(DEFAULT_COMPROMISED, DEFAULT_TARGET, 0, DashboardModel.HOURS - 1);
        }
    }

    private static void checkSize(Topology t) {
        if (t.size() > MAX_ASSETS) {
            throw new IllegalArgumentException("The network has " + t.size() + " assets; the limit is " + MAX_ASSETS);
        }
    }

    public synchronized Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", "ok");
        m.put("dataSource", dataSource);
        m.put("assets", model.topology().size());
        m.put("links", model.topology().links().size());
        m.put("events", model.eventCount());
        m.put("iocs", model.iocCount());
        m.put("patterns", model.patternCount());
        m.put("analysed", model.isAnalysed());
        m.put("warnings", warnings());
        return m;
    }

    private List<String> warnings() {
        List<String> w = new ArrayList<>();
        if (!model.unknownLogHosts().isEmpty()) {
            w.add("The alert log mentions hosts that are not in the asset list and were ignored: "
                    + String.join(", ", model.unknownLogHosts()));
        }
        if (model.eventCount() == 0) {
            w.add("The alert log is empty, so every risk score comes from exposure and reachability only");
        }
        if (model.topology().links().isEmpty()) {
            w.add("The network has no links, so no attack path can exist");
        }
        return w;
    }

    public synchronized Map<String, Object> topology() {
        Topology t = model.topology();
        List<Object> hosts = new ArrayList<>();
        for (Asset a : t.assets()) {
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("name", a.name());
            h.put("type", a.type());
            h.put("isolationCost", a.isolationCost());
            h.put("internetFacing", a.internetFacing());
            h.put("patched", a.patched());
            hosts.add(h);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("hosts", hosts);
        out.put("links", linkList());
        out.put("neverCutCost", ContainmentPlanner.INF);
        return out;
    }

    private List<Object> linkList() {
        Topology t = model.topology();
        List<Object> links = new ArrayList<>();
        List<Link> src = model.links();
        for (int i = 0; i < src.size(); i++) {
            Link l = src.get(i);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", i);
            m.put("from", t.asset(l.from()).name());
            m.put("to", t.asset(l.to()).name());
            m.put("cost", l.cost());
            m.put("bidirectional", l.bidirectional());
            m.put("neverCut", l.cost() >= ContainmentPlanner.INF);
            links.add(m);
        }
        return links;
    }

    // ---- analysis ---------------------------------------------------------------------------

    /**
     * Body: {"compromised": ["WS-Alice"], "targets": ["DB-PROD"], "fromHour": 0, "toHour": 23}.
     * Host lists may also be one comma-separated string.
     */
    public synchronized Map<String, Object> analyse(Map<String, Object> body) {
        List<String> compromised = hostList(body, "compromised");
        List<String> targets = hostList(body, "targets");
        int from = integer(body, "fromHour", 0, 0, DashboardModel.HOURS - 1);
        int to = integer(body, "toHour", DashboardModel.HOURS - 1, 0, DashboardModel.HOURS - 1);
        if (from > to) {
            throw new IllegalArgumentException("fromHour (" + from + ") must not be after toHour (" + to + ")");
        }
        for (String h : compromised) {
            if (targets.contains(h)) {
                throw new IllegalArgumentException(h + " cannot be both compromised and a protected target");
            }
        }
        model.analyse(String.join(",", compromised), String.join(",", targets), from, to);
        return result();
    }

    /** The current analysis, or {@link IllegalStateException} if none was run. */
    public synchronized Map<String, Object> result() {
        requireAnalysed();
        Topology t = model.topology();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("window", Map.of("from", model.from(), "to", model.to()));
        out.put("compromised", names(model.sources()));
        out.put("targets", names(model.targets()));

        List<Object> paths = new ArrayList<>();
        for (List<Integer> p : model.attackPaths()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("from", t.asset(p.get(0)).name());
            m.put("to", t.asset(p.get(p.size() - 1)).name());
            m.put("hops", p.size() - 1);
            m.put("path", names(p));
            paths.add(m);
        }
        out.put("attackPaths", paths);
        List<Object> unreachable = new ArrayList<>();
        for (int s : model.sources()) {
            for (int tg : model.targets()) {
                if (AttackPaths.shortestPath(t, s, tg).isEmpty()) {
                    unreachable.add(Map.of("from", t.asset(s).name(), "to", t.asset(tg).name()));
                }
            }
        }
        out.put("unreachable", unreachable);

        out.put("incidents", incidentList());
        out.put("riskStats", riskStats());
        out.put("treeBalanced", model.isBalanced());
        Map<String, Object> containment = new LinkedHashMap<>();
        containment.put("A", plan("A", "Compromised hosts stay online; cut the network downstream",
                model.plan(DashboardModel.Scenario.STRICT)));
        containment.put("B", plan("B", "Isolating the compromised host itself is allowed",
                model.plan(DashboardModel.Scenario.RELAXED)));
        out.put("containment", containment);
        out.put("links", linkList());
        out.put("costChanges", model.costChanges());
        out.put("bloom", bloom());
        out.put("warnings", warnings());
        return out;
    }

    private Map<String, Object> plan(String id, String label, ContainmentPlan p) {
        Topology t = model.topology();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scenario", id);
        m.put("label", label);
        m.put("algorithm", p.algorithm());
        m.put("feasible", p.feasible());
        m.put("totalCost", p.feasible() ? p.totalCost() : null);
        m.put("verified", p.verified());
        m.put("millis", p.nanos() / 1e6);
        List<Object> actions = new ArrayList<>();
        for (ContainmentPlan.Action a : p.actions()) {
            actions.add(Map.of("type", a.type(), "description", a.description(), "cost", a.cost()));
        }
        m.put("actions", actions);
        m.put("affectedAssets", new ArrayList<>(p.affectedAssets()));
        List<Object> blocked = new ArrayList<>();
        for (int[] l : model.blockedLinks(p)) {
            blocked.add(Map.of("from", t.asset(l[0]).name(), "to", t.asset(l[1]).name()));
        }
        m.put("blockedLinks", blocked);
        List<String> isolated = new ArrayList<>();
        for (int h : model.isolatedHosts(p)) {
            isolated.add(t.asset(h).name());
        }
        m.put("isolatedHosts", isolated);
        if (!p.feasible()) {
            m.put("message", "No finite-cost containment exists: an uncuttable link or protected host connects "
                    + "a compromised host to a target");
        }
        return m;
    }

    private List<String> names(List<Integer> indexes) {
        List<String> out = new ArrayList<>();
        for (int i : indexes) {
            out.add(model.topology().asset(i).name());
        }
        return out;
    }

    // ---- incidents --------------------------------------------------------------------------

    public synchronized Map<String, Object> incidents() {
        requireAnalysed();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("incidents", incidentList());
        out.put("riskStats", riskStats());
        out.put("treeBalanced", model.isBalanced());
        return out;
    }

    private List<Object> incidentList() {
        List<Object> list = new ArrayList<>();
        for (Incident i : model.ranked()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", i.id());
            m.put("host", i.host());
            m.put("score", i.riskScore());
            m.put("priority", DashboardModel.priority(i.riskScore()));
            m.put("reasons", i.reasons());
            m.put("windowAlerts", model.windowTotal(i.host()));
            m.put("windowPeak", model.windowPeak(i.host()));
            m.put("hourly", model.hourly(i.host()));
            list.add(m);
        }
        return list;
    }

    private Map<String, Object> riskStats() {
        DashboardModel.RiskStats s = model.riskStats();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("algorithm", "Randomized Quickselect (no sorting)");
        m.put("count", s.count());
        m.put("median", s.median());
        m.put("p75", s.p75());
        m.put("p90", s.p90());
        m.put("max", s.max());
        m.put("comparisons", s.comparisons());
        return m;
    }

    /** Body: {"host": "WS-Bob", "hour": 12, "delta": 30}. Re-scores the host and moves its incident in the tree. */
    public synchronized Map<String, Object> addEvidence(Map<String, Object> body) {
        requireAnalysed();
        String host = requiredText(body, "host").trim();
        int hour = integer(body, "hour", null, 0, DashboardModel.HOURS - 1);
        int delta = integer(body, "delta", null, 1, MAX_DELTA);
        Incident inc = model.addEvidence(host, hour, delta);
        Map<String, Object> out = incidents();
        out.put("updated", Map.of("id", inc.id(), "host", inc.host(), "score", inc.riskScore()));
        return out;
    }

    /** Body: {"host": "WS-Bob"}. Removes the host's incident from the tree. */
    public synchronized Map<String, Object> closeIncident(Map<String, Object> body) {
        requireAnalysed();
        String host = requiredText(body, "host").trim();
        if (!model.topology().has(host)) {
            throw new IllegalArgumentException("Unknown asset: " + host);
        }
        boolean closed = model.closeIncident(host);
        if (!closed) {
            throw new IllegalArgumentException("Host " + host + " has no open incident");
        }
        return incidents();
    }

    // ---- evidence search --------------------------------------------------------------------

    public synchronized Map<String, Object> iocSearch(String prefix) {
        List<String> hits = model.searchIoc(prefix);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("prefix", prefix == null ? "" : prefix.trim());
        out.put("matches", hits);
        out.put("narrowing", model.iocNarrowing(prefix));
        return out;
    }

    /** Screens one indicator: what the Bloom filter said and whether the exact check confirmed it. */
    public synchronized Map<String, Object> iocScreen(String indicator) {
        if (indicator == null || indicator.isBlank()) {
            throw new IllegalArgumentException("Enter an indicator to screen");
        }
        IocEngine.Screening s = model.screenIndicator(indicator);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("indicator", s.indicator());
        out.put("bloom", s.bloomPossible() ? "possibly present" : "definitely absent");
        out.put("bloomPossible", s.bloomPossible());
        out.put("exactConfirmed", s.exactConfirmed());
        out.put("prefixRuleMatch", s.prefixRuleMatch());
        out.put("bloomFalsePositive", s.bloomFalsePositive());
        out.put("known", s.known());
        out.put("explanation", explain(s));
        out.put("stats", bloom());
        return out;
    }

    private static String explain(IocEngine.Screening s) {
        if (s.known() && s.exactConfirmed()) {
            return "Bloom filter: possibly present. The exact check confirmed it, so this is a known indicator.";
        }
        if (s.known()) {
            return (s.bloomPossible() ? "Bloom filter: possibly present, but the exact check did not confirm it. "
                    : "Bloom filter: definitely absent as an exact indicator. ")
                    + "A prefix rule matches it, so it is still known.";
        }
        if (s.bloomFalsePositive()) {
            return "Bloom filter: possibly present, but the exact check rejected it. This was a Bloom false "
                    + "positive and it is not a known indicator.";
        }
        return "Bloom filter: definitely absent, so the exact check was skipped. Not a known indicator.";
    }

    private Map<String, Object> bloom() {
        IocEngine.BloomStats b = model.bloomStats();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("bits", b.bitSize());
        m.put("hashes", b.hashCount());
        m.put("items", b.items());
        m.put("targetRate", b.targetRate());
        m.put("estimatedRate", b.estimatedRate());
        m.put("fillRatio", b.fillRatio());
        m.put("lookups", b.lookups());
        m.put("rejectedByFilter", b.bloomRejects());
        m.put("passedFilter", b.bloomPasses());
        m.put("falsePositives", b.falsePositives());
        m.put("lookupsAvoided", b.lookupsAvoided());
        return m;
    }

    public synchronized Map<String, Object> patterns(String pattern) {
        requireAnalysed();
        Map<String, Object> out = new LinkedHashMap<>();
        if (pattern != null && !pattern.isBlank()) {
            if (pattern.length() > 200) {
                throw new IllegalArgumentException("A pattern may have at most 200 characters");
            }
            out.put("pattern", pattern.trim());
            out.put("matches", model.matchPattern(pattern));
            return out;
        }
        List<Object> all = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : model.patternMatches().entrySet()) {
            all.add(Map.of("pattern", e.getKey(), "matches", e.getValue()));
        }
        out.put("patterns", all);
        return out;
    }

    // ---- what-if and link costs -------------------------------------------------------------

    public synchronized Map<String, Object> whatIf() {
        requireAnalysed();
        List<Object> rows = new ArrayList<>();
        for (DashboardModel.WhatIfRow r : model.whatIf()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("host", r.host());
            m.put("type", r.type());
            m.put("internetFacing", r.internetFacing());
            m.put("patched", r.patched());
            m.put("exposedAndUnpatched", r.exposedAndUnpatched());
            m.put("reaches", r.reaches());
            m.put("hops", r.hops());
            m.put("feasibleA", r.feasibleA());
            m.put("costA", r.feasibleA() ? r.costA() : null);
            m.put("feasibleB", r.feasibleB());
            m.put("costB", r.feasibleB() ? r.costB() : null);
            rows.add(m);
        }
        return Map.of("rows", rows);
    }

    /** Body: {"cost": 25}. A cost of 1,000,000 marks the link as never to be cut. */
    public synchronized Map<String, Object> setLinkCost(int index, Map<String, Object> body) {
        requireAnalysed();
        int cost = integer(body, "cost", null, 0, ContainmentPlanner.INF);
        model.setLinkCost(index, cost);
        return result();
    }

    public synchronized Map<String, Object> resetLinkCosts() {
        requireAnalysed();
        model.resetLinkCosts();
        return result();
    }

    // ---- benchmarks and report --------------------------------------------------------------

    /**
     * Runs the scaling benchmarks (seeded, three sizes per technique, each against a baseline).
     * Only one run at a time; the model lock is not held, so the rest of the API stays responsive.
     */
    public Map<String, Object> benchmarks(String profileName) {
        ScalingBenchmarks.Profile profile = "full".equalsIgnoreCase(profileName)
                ? ScalingBenchmarks.Profile.FULL : ScalingBenchmarks.Profile.QUICK;
        if (profileName != null && !profileName.isBlank()
                && !profileName.equalsIgnoreCase("full") && !profileName.equalsIgnoreCase("quick")) {
            throw new IllegalArgumentException("profile must be quick or full");
        }
        if (!benchmarkRunning.compareAndSet(false, true)) {
            throw new IllegalStateException("A benchmark run is already in progress; try again in a few seconds");
        }
        try {
            List<ScalingBenchmarks.Experiment> experiments = ScalingBenchmarks.run(profile);
            List<Object> list = new ArrayList<>();
            for (ScalingBenchmarks.Experiment e : experiments) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", e.id());
                m.put("technique", e.technique());
                m.put("baseline", e.baseline());
                m.put("workload", e.workload());
                m.put("allMatch", e.allMatch());
                m.put("conclusion", e.conclusion());
                List<Object> rows = new ArrayList<>();
                for (ScalingBenchmarks.Row r : e.rows()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("size", r.size());
                    row.put("techniqueMs", r.fastMs());
                    row.put("baselineMs", r.baselineMs());
                    row.put("speedup", r.speedup());
                    row.put("match", r.match());
                    row.put("detail", r.detail());
                    rows.add(row);
                }
                m.put("rows", rows);
                list.add(m);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("profile", profile.name().toLowerCase());
            out.put("runs", com.breachpath.engine.Benchmarks.RUNS);
            out.put("note", "Median of " + com.breachpath.engine.Benchmarks.RUNS
                    + " runs after one warm-up run, seeded synthetic data, one machine. "
                    + "Differences of a few percent are noise.");
            out.put("experiments", list);
            lastBenchmark = out;
            return out;
        } finally {
            benchmarkRunning.set(false);
        }
    }

    /** The most recent benchmark result, or null if none was run in this process. */
    public Map<String, Object> lastBenchmark() {
        return lastBenchmark;
    }

    /** Self-contained HTML report (incident ranking, both containment plans, what-if table). */
    public synchronized String reportHtml() {
        requireAnalysed();
        return ReportWriter.html(model, LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
    }

    // ---- request parsing --------------------------------------------------------------------

    private void requireAnalysed() {
        if (!model.isAnalysed()) {
            throw new IllegalStateException("Run an analysis first (choose compromised hosts and targets)");
        }
    }

    private static String requiredText(Map<String, Object> body, String key) {
        Object v = body.get(key);
        if (v == null) {
            throw new IllegalArgumentException("Missing field: " + key);
        }
        if (!(v instanceof String s)) {
            throw new IllegalArgumentException("Field " + key + " must be text");
        }
        return s;
    }

    private static String optionalText(Map<String, Object> body, String key) {
        Object v = body.get(key);
        if (v == null) {
            return "";
        }
        if (!(v instanceof String s)) {
            throw new IllegalArgumentException("Field " + key + " must be text");
        }
        return s;
    }

    /** Reads an integer field; {@code fallback} null means the field is required. */
    private static int integer(Map<String, Object> body, String key, Integer fallback, int min, int max) {
        Object v = body.get(key);
        if (v == null) {
            if (fallback == null) {
                throw new IllegalArgumentException("Missing field: " + key);
            }
            return fallback;
        }
        if (!(v instanceof Number n) || n.doubleValue() != Math.rint(n.doubleValue())) {
            throw new IllegalArgumentException("Field " + key + " must be a whole number");
        }
        long value = n.longValue();
        if (value < min || value > max) {
            throw new IllegalArgumentException("Field " + key + " must be between " + min + " and " + max
                    + " but was " + value);
        }
        return (int) value;
    }

    private List<String> hostList(Map<String, Object> body, String key) {
        Object v = body.get(key);
        List<String> out = new ArrayList<>();
        if (v instanceof String s) {
            for (String part : s.split(",")) {
                if (!part.isBlank()) {
                    out.add(part.trim());
                }
            }
        } else if (v instanceof List<?> list) {
            for (Object o : list) {
                if (!(o instanceof String s)) {
                    throw new IllegalArgumentException("Field " + key + " must be a list of host names");
                }
                if (!s.isBlank()) {
                    out.add(s.trim());
                }
            }
        } else if (v != null) {
            throw new IllegalArgumentException("Field " + key + " must be a list of host names");
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("Choose at least one host in " + key);
        }
        if (out.size() > MAX_LIST) {
            throw new IllegalArgumentException("Field " + key + " has too many hosts (limit " + MAX_LIST + ")");
        }
        for (String h : out) {
            if (!model.topology().has(h)) {
                throw new IllegalArgumentException("Unknown asset: " + h);
            }
        }
        return new ArrayList<>(new java.util.LinkedHashSet<>(out));
    }
}