package com.breachpath.engine;

import com.breachpath.model.Link;
import com.breachpath.model.Topology;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Reachability and shortest attack path over the host graph (used for reports and for verifying cuts). */
public final class AttackPaths {
    private AttackPaths() {
    }

    /** Encodes the directed link a -> b as one number. */
    public static long linkKey(int n, int a, int b) {
        return (long) a * n + b;
    }

    private static List<List<Integer>> adjacency(Topology topo) {
        List<List<Integer>> adj = new ArrayList<>();
        for (int i = 0; i < topo.size(); i++) {
            adj.add(new ArrayList<>());
        }
        for (Link l : topo.links()) {
            adj.get(l.from()).add(l.to());
            if (l.bidirectional()) {
                adj.get(l.to()).add(l.from());
            }
        }
        return adj;
    }

    /** Hosts reachable from the sources without passing through blocked hosts or blocked directed links. */
    public static boolean[] reachable(Topology topo, Collection<Integer> sources,
                                      Set<Integer> blockedHosts, Set<Long> blockedLinks) {
        int n = topo.size();
        List<List<Integer>> adj = adjacency(topo);
        boolean[] seen = new boolean[n];
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        for (int s : sources) {
            if (!blockedHosts.contains(s) && !seen[s]) {
                seen[s] = true;
                queue.add(s);
            }
        }
        while (!queue.isEmpty()) {
            int u = queue.poll();
            for (int v : adj.get(u)) {
                if (seen[v] || blockedHosts.contains(v) || blockedLinks.contains(linkKey(n, u, v))) {
                    continue;
                }
                seen[v] = true;
                queue.add(v);
            }
        }
        return seen;
    }

    /** Shortest path (fewest hops) from src to dst, or an empty list if dst is unreachable. */
    public static List<Integer> shortestPath(Topology topo, int src, int dst) {
        int n = topo.size();
        List<List<Integer>> adj = adjacency(topo);
        int[] parent = new int[n];
        java.util.Arrays.fill(parent, -1);
        parent[src] = src;
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        queue.add(src);
        while (!queue.isEmpty() && parent[dst] == -1) {
            int u = queue.poll();
            for (int v : adj.get(u)) {
                if (parent[v] == -1) {
                    parent[v] = u;
                    queue.add(v);
                }
            }
        }
        if (parent[dst] == -1) {
            return List.of();
        }
        List<Integer> path = new ArrayList<>();
        for (int v = dst; v != src; v = parent[v]) {
            path.add(v);
        }
        path.add(src);
        Collections.reverse(path);
        return path;
    }
}
