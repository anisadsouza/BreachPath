package com.breachpath.ui;

import com.breachpath.engine.AttackPaths;
import com.breachpath.engine.Benchmarks;
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
import com.breachpath.graph.MaxFlowAlgorithm;
import com.breachpath.model.Incident;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
import com.breachpath.storage.DataLoader;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Console report for BreachPath.
 *
 * Usage: java com.breachpath.ui.ConsoleApp [dataDir] [compromisedHosts] [targets] [benchmark]
 * Hosts may be comma separated, e.g. WS-Alice,WS-Bob. Defaults: data WS-Alice DB-PROD
 */
public final class ConsoleApp {
    private static final int WINDOW_FROM = 0;
    private static final int WINDOW_TO = 23;

    private ConsoleApp() {
    }

    public static void main(String[] args) throws IOException {
        boolean benchmark = false;
        List<String> pos = new ArrayList<>();
        for (String a : args) {
            if (a.equalsIgnoreCase("benchmark")) {
                benchmark = true;
            } else {
                pos.add(a);
            }
        }
        Path dir = Path.of(pos.size() > 0 ? pos.get(0) : "data");
        String compromisedArg = pos.size() > 1 ? pos.get(1) : "WS-Alice";
        String targetArg = pos.size() > 2 ? pos.get(2) : "DB-PROD";

        // 1. Load -------------------------------------------------------------
        heading("1. Load the enterprise environment");
        Topology topo = DataLoader.loadTopology(dir.resolve("assets.csv"), dir.resolve("network_edges.csv"));
        List<SecurityEvent> events = DataLoader.loadEvents(dir.resolve("security_events.csv"));
        IocEngine iocEngine = IocEngine.fromLines(DataLoader.loadLines(dir.resolve("iocs.txt")));
        List<String> patternLines = DataLoader.loadLines(dir.resolve("patterns.txt"));
        System.out.printf("%d assets, %d links, %d log rows, %d IOC entries, %d hunting patterns%n",
                topo.size(), topo.links().size(), events.size(), iocEngine.size(), patternLines.size());

        List<Integer> sources = indexes(topo, compromisedArg);
        List<Integer> targets = indexes(topo, targetArg);

        // 2. Attack paths -----------------------------------------------------
        heading("2. Attack paths (shortest route per compromised host / target)");
        for (int s : sources) {
            for (int t : targets) {
                List<Integer> path = AttackPaths.shortestPath(topo, s, t);
                if (path.isEmpty()) {
                    System.out.printf("%s -> %s: no path%n", topo.asset(s).name(), topo.asset(t).name());
                } else {
                    List<String> names = new ArrayList<>();
                    for (int h : path) {
                        names.add(topo.asset(h).name());
                    }
                    System.out.printf("%s (%d hops)%n", String.join(" -> ", names), path.size() - 1);
                }
            }
        }

        // 3. Investigate ------------------------------------------------------
        heading("3. Investigate the evidence");
        EventTimeline timeline = new EventTimeline(events, 24);
        PatternEngine patternEngine = new PatternEngine(
                events.stream().map(SecurityEvent::command).filter(c -> !c.isEmpty()).toList());

        System.out.println("Wildcard hunting ('.' = one unknown character):");
        Set<String> matchedCommands = new HashSet<>();
        for (String p : patternLines) {
            List<String> hits = patternEngine.match(p);
            matchedCommands.addAll(hits);
            System.out.printf("  %-12s -> %s%n", p, hits.isEmpty() ? "(no match)" : hits);
        }
        System.out.println("IOC prefix search examples:");
        for (String p : new String[]{"update", "203.0", "c:\\users"}) {
            System.out.printf("  %-10s -> %s%n", p, iocEngine.search(p));
        }

        Map<String, HostEvidence> evidence = HostEvidence.collect(events, iocEngine, matchedCommands);
        System.out.println();
        System.out.printf("Alert activity, hours %d-%d (segment tree range queries):%n", WINDOW_FROM, WINDOW_TO);
        System.out.printf("  %-12s %8s %12s %12s%n", "host", "total", "peak/hour", "hours 0-5");
        for (String host : timeline.hosts()) {
            System.out.printf("  %-12s %8d %12d %12d%n", host,
                    timeline.total(host, WINDOW_FROM, WINDOW_TO),
                    timeline.peak(host, WINDOW_FROM, WINDOW_TO),
                    timeline.total(host, 0, 5));
        }

        // 4. Prioritise -------------------------------------------------------
        heading("4. Prioritise incidents (red-black tree)");
        Set<String> reaching = new HashSet<>();
        for (int i = 0; i < topo.size(); i++) {
            boolean[] reach = AttackPaths.reachable(topo, List.of(i), Set.of(), Set.of());
            for (int t : targets) {
                if (reach[t] && i != t) {
                    reaching.add(topo.asset(i).name());
                }
            }
        }
        RiskScorer scorer = new RiskScorer();
        IncidentIndex incidents = new IncidentIndex();
        for (String host : timeline.hosts()) {
            if (!topo.has(host)) {
                System.out.println("Skipping unknown host in log: " + host);
                continue;
            }
            RiskAssessment ra = assess(host, topo, timeline, evidence, reaching, scorer);
            incidents.open(host, ra.score(), ra.reasons());
        }
        System.out.printf("%d incidents opened, tree balanced: %s%n", incidents.size(), incidents.isBalanced());
        printTop(incidents, 5);

        List<Incident> all = incidents.top(incidents.size());
        Incident lowest = all.get(all.size() - 1);
        timeline.addAlerts(lowest.host(), 12, 30);
        RiskAssessment updated = assess(lowest.host(), topo, timeline, evidence, reaching, scorer);
        incidents.updateScore(lowest.id(), updated.score(), "new evidence: +30 alerts at hour 12");
        int rank = 1;
        for (Incident i : incidents.top(incidents.size())) {
            if (i.id() == lowest.id()) {
                break;
            }
            rank++;
        }
        System.out.printf("%nNew evidence: +30 alerts on %s at hour 12 -> score %d -> %d, now rank %d of %d (balanced: %s)%n",
                lowest.host(), lowest.riskScore(), updated.score(), rank, incidents.size(), incidents.isBalanced());
        printTop(incidents, 5);

        // 5 & 6. Containment --------------------------------------------------
        heading("5. Containment options (max flow / min cut with node splitting)");
        ContainmentPlanner planner = new ContainmentPlanner();
        MaxFlowAlgorithm ek = new EdmondsKarp();
        ContainmentPlan strict = planner.plan(topo, sources, targets, false, ek);
        ContainmentPlan relaxed = planner.plan(topo, sources, targets, true, ek);

        System.out.println("Scenario A: compromised hosts stay online; cut the network downstream");
        printPlan(strict);
        System.out.println();
        System.out.println("Scenario B: isolating the compromised host itself is allowed");
        printPlan(relaxed);

        heading("6. Algorithm timing on this network");
        System.out.printf("%-22s scenario A: cost %-5d %.3f ms%n", strict.algorithm(), strict.totalCost(), strict.nanos() / 1e6);
        System.out.printf("%-22s scenario B: cost %-5d %.3f ms%n", relaxed.algorithm(), relaxed.totalCost(), relaxed.nanos() / 1e6);

        // 7. Benchmarks -------------------------------------------------------
        if (benchmark) {
            heading("7. Performance evaluation");
            Benchmarks.runAll();
        } else {
            System.out.println();
            System.out.println("Tip: add the word 'benchmark' to the command to run the performance experiments.");
        }
    }

    private static RiskAssessment assess(String host, Topology topo, EventTimeline timeline,
                                         Map<String, HostEvidence> evidence, Set<String> reaching,
                                         RiskScorer scorer) {
        HostEvidence ev = evidence.getOrDefault(host, HostEvidence.empty(host));
        var asset = topo.asset(topo.indexOf(host));
        return scorer.score(host, WINDOW_FROM, WINDOW_TO, timeline,
                ev.iocs().size(), ev.commands().size(), reaching.contains(host),
                asset.internetFacing(), asset.patched());
    }

    private static void printTop(IncidentIndex incidents, int k) {
        System.out.printf("  %-4s %-12s %-6s %s%n", "id", "host", "score", "why");
        for (Incident i : incidents.top(k)) {
            System.out.printf("  %-4d %-12s %-6d %s%n", i.id(), i.host(), i.riskScore(),
                    String.join("; ", i.reasons()));
        }
    }

    private static void printPlan(ContainmentPlan plan) {
        if (!plan.feasible()) {
            System.out.println("  No finite-cost containment exists.");
            return;
        }
        for (ContainmentPlan.Action a : plan.actions()) {
            System.out.printf("  - %-34s cost %d%n", a.description(), a.cost());
        }
        System.out.printf("  Total cost: %d | assets affected: %s%n", plan.totalCost(), new TreeSet<>(plan.affectedAssets()));
        System.out.println("  Verified (targets unreachable after the cut): " + plan.verified());
    }

    private static List<Integer> indexes(Topology topo, String csv) {
        List<Integer> out = new ArrayList<>();
        for (String name : csv.split(",")) {
            out.add(topo.indexOf(name.trim()));
        }
        return out;
    }

    private static void heading(String text) {
        System.out.println();
        System.out.println(text.toUpperCase(Locale.ROOT));
        System.out.println("-".repeat(text.length()));
    }
}