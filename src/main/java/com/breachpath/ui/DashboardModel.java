package com.breachpath.ui;

import com.breachpath.engine.AttackPaths;
import com.breachpath.engine.ContainmentPlan;
import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.EventTimeline;
import com.breachpath.engine.HostEvidence;
import com.breachpath.engine.IncidentIndex;
import com.breachpath.engine.IocEngine;
import com.breachpath.engine.PatternEngine;
import com.breachpath.engine.RiskAssessment;
import com.breachpath.engine.RiskScorer;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.model.Asset;
import com.breachpath.model.Incident;
import com.breachpath.model.IncidentKey;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
import com.breachpath.rbtree.RedBlackTree;
import com.breachpath.storage.DataLoader;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * All dashboard logic with no JavaFX dependency, so it can be unit-tested headlessly.
 * It wires the existing engines together the same way the console report does.
 */
public final class DashboardModel {
    public static final int HOURS = 24;

    /** Which containment scenario the dashboard is showing. */
    public enum Scenario { NONE, STRICT, RELAXED }

    private final Topology topology;
    private final List<SecurityEvent> events;
    private final IocEngine iocEngine;
    private final List<String> patternLines;

    private EventTimeline timeline;
    private IncidentIndex incidents;
    private Map<String, HostEvidence> evidence;
    private Set<String> reaching;
    private PatternEngine patternEngine;
    private Map<String, List<String>> patternHits = new LinkedHashMap<>();
    private final Map<String, Integer> incidentByHost = new HashMap<>();
    private final RiskScorer scorer = new RiskScorer();

    private List<Integer> sources = List.of();
    private List<Integer> targets = List.of();
    private int from;
    private int to;
    private List<List<Integer>> attackPaths = List.of();
    private ContainmentPlan strictEk;
    private ContainmentPlan relaxedEk;
    private boolean analysed;

    public DashboardModel(Topology topology, List<SecurityEvent> events, IocEngine iocEngine,
                          List<String> patternLines) {
        this.topology = topology;
        this.events = List.copyOf(events);
        this.iocEngine = iocEngine;
        this.patternLines = List.copyOf(patternLines);
    }

    public static DashboardModel load(Path dir) throws IOException {
        Topology topo = DataLoader.loadTopology(dir.resolve("assets.csv"), dir.resolve("network_edges.csv"));
        List<SecurityEvent> events = DataLoader.loadEvents(dir.resolve("security_events.csv"));
        IocEngine ioc = IocEngine.fromLines(DataLoader.loadLines(dir.resolve("iocs.txt")));
        List<String> patterns = DataLoader.loadLines(dir.resolve("patterns.txt"));
        return new DashboardModel(topo, events, ioc, patterns);
    }

    /**
     * (Re)runs the whole analysis from the raw log: attack paths, evidence, incident scoring and
     * both containment scenarios. This also discards any evidence added with {@link #addEvidence}.
     *
     * @throws IllegalArgumentException for unknown hosts, a bad window, or a host that is both
     *                                  compromised and a target
     */
    public void analyse(String compromisedCsv, String targetsCsv, int fromHour, int toHour) {
        if (fromHour < 0 || toHour >= HOURS || fromHour > toHour) {
            throw new IllegalArgumentException("Window must satisfy 0 <= from <= to <= " + (HOURS - 1));
        }
        List<Integer> src = indexes(compromisedCsv);
        List<Integer> tgt = indexes(targetsCsv);
        if (src.isEmpty() || tgt.isEmpty()) {
            throw new IllegalArgumentException("Enter at least one compromised host and one target");
        }

        ContainmentPlanner planner = new ContainmentPlanner();
        ContainmentPlan sEk = planner.plan(topology, src, tgt, false, new EdmondsKarp());
        ContainmentPlan rEk = planner.plan(topology, src, tgt, true, new EdmondsKarp());

        this.sources = src;
        this.targets = tgt;
        this.from = fromHour;
        this.to = toHour;
        this.strictEk = sEk;
        this.relaxedEk = rEk;

        List<List<Integer>> paths = new ArrayList<>();
        for (int s : src) {
            for (int t : tgt) {
                List<Integer> p = AttackPaths.shortestPath(topology, s, t);
                if (!p.isEmpty()) {
                    paths.add(p);
                }
            }
        }
        this.attackPaths = paths;

        this.timeline = new EventTimeline(events, HOURS);
        PatternEngine patternEngine = new PatternEngine(
                events.stream().map(SecurityEvent::command).filter(c -> !c.isEmpty()).toList());
        this.patternEngine = patternEngine;
        Set<String> matched = new HashSet<>();
        Map<String, List<String>> hitsByPattern = new LinkedHashMap<>();
        for (String p : patternLines) {
            List<String> hits = patternEngine.match(p);
            hitsByPattern.put(p, hits);
            matched.addAll(hits);
        }
        this.patternHits = hitsByPattern;
        this.evidence = HostEvidence.collect(events, iocEngine, matched);

        Set<String> reach = new HashSet<>();
        for (int i = 0; i < topology.size(); i++) {
            boolean[] r = AttackPaths.reachable(topology, List.of(i), Set.of(), Set.of());
            for (int t : tgt) {
                if (r[t] && i != t) {
                    reach.add(topology.asset(i).name());
                }
            }
        }
        this.reaching = reach;

        this.incidents = new IncidentIndex();
        this.incidentByHost.clear();
        for (String host : timeline.hosts()) {
            if (!topology.has(host)) {
                continue;
            }
            RiskAssessment ra = assess(host);
            Incident inc = incidents.open(host, ra.score(), ra.reasons());
            incidentByHost.put(host, inc.id());
        }
        this.analysed = true;
    }

    /**
     * New evidence: adds alerts to one hour of a host (segment-tree point update), re-scores the
     * host and moves its incident in the red-black tree (opening one if the host had none).
     */
    public Incident addEvidence(String host, int hour, int delta) {
        requireAnalysed();
        if (!topology.has(host)) {
            throw new IllegalArgumentException("Unknown asset: " + host);
        }
        timeline.addAlerts(host, hour, delta);
        RiskAssessment ra = assess(host);
        String note = "new evidence: +" + delta + " alerts at hour " + hour;
        Integer id = incidentByHost.get(host);
        if (id == null) {
            List<String> reasons = new ArrayList<>(ra.reasons());
            reasons.add(note);
            Incident inc = incidents.open(host, ra.score(), reasons);
            incidentByHost.put(host, inc.id());
            return inc;
        }
        incidents.updateScore(id, ra.score(), note);
        return incidents.find(id);
    }

    private RiskAssessment assess(String host) {
        HostEvidence ev = evidence.getOrDefault(host, HostEvidence.empty(host));
        Asset asset = topology.asset(topology.indexOf(host));
        return scorer.score(host, from, to, timeline, ev.iocs().size(), ev.commands().size(),
                reaching.contains(host), asset.internetFacing(), asset.patched());
    }

    // ---- read access for the UI -------------------------------------------------------------

    public boolean isAnalysed() {
        return analysed;
    }

    public Topology topology() {
        return topology;
    }

    public List<Integer> sources() {
        return sources;
    }

    public List<Integer> targets() {
        return targets;
    }

    public int from() {
        return from;
    }

    public int to() {
        return to;
    }

    public List<List<Integer>> attackPaths() {
        return attackPaths;
    }

    /** Each wildcard hunting pattern with the observed commands it matched ('.' = one unknown character). */
    public Map<String, List<String>> patternMatches() {
        requireAnalysed();
        return patternHits;
    }

    /** Known indicators (and prefix rules, shown with '*') that start with the typed prefix. */
    public List<String> searchIoc(String prefix) {
        return iocEngine.search(prefix == null ? "" : prefix.trim());
    }

    /** Closes the host's incident (removes it from the red-black tree). False if it has none. */
    public boolean closeIncident(String host) {
        requireAnalysed();
        Integer id = incidentByHost.remove(host);
        return id != null && incidents.close(id);
    }

    /** A snapshot of the incident red-black tree: nodes in key order with colour, depth and parent. */
    public List<RedBlackTree.NodeView<IncidentKey, Incident>> treeView() {
        requireAnalysed();
        return incidents.treeView();
    }

    /** The stored segment-tree ranges combined to answer the current window for this host. */
    public List<int[]> coveringRanges(String host) {
        requireAnalysed();
        return timeline.coveringRanges(host, from, to);
    }

    /** For each character typed, how many known indicators still match the prefix so far. */
    public List<Integer> iocNarrowing(String text) {
        String t = text == null ? "" : text.trim();
        List<Integer> counts = new ArrayList<>();
        for (int k = 1; k <= t.length(); k++) {
            counts.add(searchIoc(t.substring(0, k)).size());
        }
        return counts;
    }

    /** Observed commands matching a wildcard pattern ('.' = one unknown character). */
    public List<String> matchPattern(String pattern) {
        requireAnalysed();
        if (pattern == null || pattern.isBlank()) {
            return List.of();
        }
        return patternEngine.match(pattern.trim());
    }

    /**
     * One row of the what-if sweep: if this host were the only compromised one, how far is it from
     * the targets and what would the cheapest containment cost?
     *
     * @param hops      steps along the shortest attack path (0 when the host cannot reach a target)
     * @param feasibleA false when an uncuttable link makes containment impossible without isolating it
     * @param costA     cheapest cut when the compromised host must stay online (Scenario A)
     * @param costB     cheapest cut when the compromised host itself may be isolated (Scenario B)
     */
    public record WhatIfRow(String host, String type, boolean internetFacing, boolean patched,
                            boolean reaches, int hops,
                            boolean feasibleA, int costA, boolean feasibleB, int costB) {
        /** Internet-facing and unpatched: the first hosts to fix. */
        public boolean exposedAndUnpatched() {
            return internetFacing && !patched;
        }
    }

    /**
     * Treats every non-target host in turn as the only compromised host. Hosts that can reach a
     * target come first; among those, internet-facing unpatched hosts, then the hardest to contain
     * (highest cost), then the nearest.
     */
    public List<WhatIfRow> whatIf() {
        requireAnalysed();
        ContainmentPlanner planner = new ContainmentPlanner();
        List<WhatIfRow> rows = new ArrayList<>();
        for (int i = 0; i < topology.size(); i++) {
            if (targets.contains(i)) {
                continue;
            }
            int best = Integer.MAX_VALUE;
            for (int t : targets) {
                List<Integer> path = AttackPaths.shortestPath(topology, i, t);
                if (!path.isEmpty()) {
                    best = Math.min(best, path.size() - 1);
                }
            }
            boolean reaches = best != Integer.MAX_VALUE;
            ContainmentPlan a = planner.plan(topology, List.of(i), targets, false, new EdmondsKarp());
            ContainmentPlan b = planner.plan(topology, List.of(i), targets, true, new EdmondsKarp());
            Asset asset = topology.asset(i);
            rows.add(new WhatIfRow(asset.name(), asset.type(), asset.internetFacing(), asset.patched(), reaches,
                    reaches ? best : 0, a.feasible(), a.feasible() ? a.totalCost() : 0,
                    b.feasible(), b.feasible() ? b.totalCost() : 0));
        }
        rows.sort((x, y) -> {
            if (x.reaches() != y.reaches()) {
                return x.reaches() ? -1 : 1;
            }
            if (x.exposedAndUnpatched() != y.exposedAndUnpatched()) {
                return x.exposedAndUnpatched() ? -1 : 1;
            }
            int cx = x.feasibleA() ? x.costA() : Integer.MAX_VALUE;
            int cy = y.feasibleA() ? y.costA() : Integer.MAX_VALUE;
            if (cx != cy) {
                return Integer.compare(cy, cx);
            }
            if (x.hops() != y.hops()) {
                return Integer.compare(x.hops(), y.hops());
            }
            return x.host().compareTo(y.host());
        });
        return rows;
    }

    public boolean isBalanced() {
        requireAnalysed();
        return incidents.isBalanced();
    }

    /** All incidents, highest risk first. */
    public List<Incident> ranked() {
        requireAnalysed();
        return incidents.top(incidents.size());
    }

    /** Incident for a host, or null. */
    public Incident incidentFor(String host) {
        requireAnalysed();
        Integer id = incidentByHost.get(host);
        return id == null ? null : incidents.find(id);
    }

    /** Alerts of the host in every hour 0..23 (each value is a one-hour segment-tree query). */
    public int[] hourly(String host) {
        requireAnalysed();
        int[] out = new int[HOURS];
        for (int h = 0; h < HOURS; h++) {
            out[h] = timeline.total(host, h, h);
        }
        return out;
    }

    public int windowTotal(String host) {
        requireAnalysed();
        return timeline.total(host, from, to);
    }

    public int windowPeak(String host) {
        requireAnalysed();
        return timeline.peak(host, from, to);
    }

    public ContainmentPlan plan(Scenario s) {
        requireAnalysed();
        switch (s) {
            case STRICT:
                return strictEk;
            case RELAXED:
                return relaxedEk;
            default:
                return null;
        }
    }

    /** Directed links {from, to} (host indexes) blocked by a plan. */
    public List<int[]> blockedLinks(ContainmentPlan plan) {
        List<int[]> out = new ArrayList<>();
        if (plan == null || !plan.feasible()) {
            return out;
        }
        for (ContainmentPlan.Action a : plan.actions()) {
            if (a.type().equals("BLOCK_LINK")) {
                String[] names = a.description().substring("Block link ".length()).split(" -> ");
                out.add(new int[]{topology.indexOf(names[0]), topology.indexOf(names[1])});
            }
        }
        return out;
    }

    /** Host indexes isolated by a plan. */
    public Set<Integer> isolatedHosts(ContainmentPlan plan) {
        Set<Integer> out = new LinkedHashSet<>();
        if (plan == null || !plan.feasible()) {
            return out;
        }
        for (ContainmentPlan.Action a : plan.actions()) {
            if (a.type().equals("ISOLATE_HOST")) {
                out.add(topology.indexOf(a.description().substring("Isolate host ".length())));
            }
        }
        return out;
    }

    private List<Integer> indexes(String csv) {
        List<Integer> out = new ArrayList<>();
        if (csv == null) {
            return out;
        }
        for (String name : csv.split(",")) {
            if (!name.isBlank()) {
                out.add(topology.indexOf(name.trim()));
            }
        }
        return out;
    }

    private void requireAnalysed() {
        if (!analysed) {
            throw new IllegalStateException("Call analyse() first");
        }
    }
}