package com.breachpath.engine;

import com.breachpath.graph.FlowNetwork;
import com.breachpath.graph.MaxFlowAlgorithm;
import com.breachpath.graph.MaxFlowResult;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Turns the network into a flow network and finds the cheapest set of actions that separates the
 * compromised hosts from the protected targets.
 *
 * <p>Node splitting: every host i becomes in(i) = 2i and out(i) = 2i+1, joined by an edge whose
 * capacity is the host's isolation cost, so cutting that edge means "isolate the host". A link
 * a -> b becomes out(a) -> in(b) with the link's blocking cost. A super source feeds every
 * compromised host; every target feeds a super sink. Targets (and, optionally, compromised hosts)
 * get an INF host edge because they must not be cut.
 */
public class ContainmentPlanner {
    /** Capacity for edges that must never be cut. */
    public static final int INF = 1_000_000;

    public ContainmentPlan plan(Topology topo, Collection<Integer> sources, Collection<Integer> targets,
                                boolean allowIsolateSources, MaxFlowAlgorithm algorithm) {
        Set<Integer> src = new LinkedHashSet<>(sources);
        Set<Integer> tgt = new LinkedHashSet<>(targets);
        if (src.isEmpty() || tgt.isEmpty()) {
            throw new IllegalArgumentException("Need at least one compromised host and one target");
        }
        for (int s : src) {
            if (tgt.contains(s)) {
                throw new IllegalArgumentException(
                        "Host is both compromised and a protected target: " + topo.asset(s).name());
            }
        }

        int n = topo.size();
        int superSource = 2 * n;
        int superSink = 2 * n + 1;
        FlowNetwork net = new FlowNetwork(2 * n + 2);

        for (int i = 0; i < n; i++) {
            int cap = topo.asset(i).isolationCost();
            if (tgt.contains(i) || (src.contains(i) && !allowIsolateSources)) {
                cap = INF;
            }
            net.addEdge(2 * i, 2 * i + 1, cap);
        }
        for (Link l : topo.links()) {
            net.addEdge(2 * l.from() + 1, 2 * l.to(), l.cost());
            if (l.bidirectional()) {
                net.addEdge(2 * l.to() + 1, 2 * l.from(), l.cost());
            }
        }
        for (int s : src) {
            net.addEdge(superSource, 2 * s, INF);
        }
        for (int t : tgt) {
            net.addEdge(2 * t + 1, superSink, INF);
        }

        MaxFlowResult r = algorithm.compute(net, superSource, superSink);
        if (r.maxFlow() >= INF) {
            return new ContainmentPlan(r.algorithm(), false, r.maxFlow(), List.of(), Set.of(), false, r.nanos());
        }

        List<ContainmentPlan.Action> actions = new ArrayList<>();
        Set<Integer> blockedHosts = new HashSet<>();
        Set<Long> blockedLinks = new HashSet<>();
        Set<String> affected = new TreeSet<>();

        for (int[] e : r.cutEdges()) {
            int u = e[0];
            int v = e[1];
            if (u < 2 * n && u % 2 == 0 && v == u + 1) {
                int host = u / 2;
                String name = topo.asset(host).name();
                actions.add(new ContainmentPlan.Action("ISOLATE_HOST", "Isolate host " + name, e[2]));
                blockedHosts.add(host);
                affected.add(name);
            } else if (u < 2 * n && v < 2 * n && u % 2 == 1 && v % 2 == 0) {
                int a = u / 2;
                int b = v / 2;
                String an = topo.asset(a).name();
                String bn = topo.asset(b).name();
                actions.add(new ContainmentPlan.Action("BLOCK_LINK", "Block link " + an + " -> " + bn, e[2]));
                blockedLinks.add(AttackPaths.linkKey(n, a, b));
                affected.add(an);
                affected.add(bn);
            }
        }

        boolean[] reach = AttackPaths.reachable(topo, src, blockedHosts, blockedLinks);
        boolean verified = true;
        for (int t : tgt) {
            if (reach[t]) {
                verified = false;
            }
        }
        return new ContainmentPlan(r.algorithm(), true, r.cutCost(), actions, affected, verified, r.nanos());
    }
}
