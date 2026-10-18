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
import com.breachpath.graph.FordFulkerson;
import com.breachpath.model.Incident;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
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
    private Map<String, List<String>> patternHits = new LinkedHashMap<>();
    private final Map<String, Integer> incidentByHost = new HashMap<>();
    private final RiskScorer scorer = new RiskScorer();

    private List<Integer> sources = List.of();
    private List<Integer> targets = List.of();
    private int from;
    private int to;
    private List<List<Integer>> attackPaths = List.of();
    private ContainmentPlan strictEk;
    private ContainmentPlan strictFf;
    private ContainmentPlan relaxedEk;
    private ContainmentPlan relaxedFf;
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
        ContainmentPlan sFf = planner.plan(topology, src, tgt, false, new FordFulkerson());
        ContainmentPlan rEk = planner.plan(topology, src, tgt, true, new EdmondsKarp());
        ContainmentPlan rFf = planner.plan(topology, src, tgt, true, new FordFulkerson());

        this.sources = src;
        this.targets = tgt;
        this.from = fromHour;
        this.to = toHour;
        this.strictEk = sEk;
        this.strictFf = sFf;
        this.relaxedEk = rEk;
        this.relaxedFf = rFf;

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
        return scorer.score(host, from, to, timeline, ev.iocs().size(), ev.commands().size(),
                reaching.contains(host));
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

    public ContainmentPlan plan(Scenario s, boolean useFordFulkerson) {
        requireAnalysed();
        switch (s) {
            case STRICT:
                return useFordFulkerson ? strictFf : strictEk;
            case RELAXED:
                return useFordFulkerson ? relaxedFf : relaxedEk;
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