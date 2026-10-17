package com.breachpath.graph;

import java.util.List;

/**
 * Reference implementation for small graphs: tries every subset of removable edges and keeps
 * the cheapest one that disconnects the source from the sink. Used to validate the flow algorithms.
 */
public final class BruteForceMinCut {
    private BruteForceMinCut() {
    }

    /**
     * @param unremovableAtLeast edges with capacity >= this value may not be cut
     * @return the minimum cut cost, or -1 if no allowed cut disconnects source from sink
     */
    public static int minCutCost(FlowNetwork net, int s, int t, int unremovableAtLeast) {
        List<int[]> edges = net.edges();
        int m = edges.size();
        if (m > 22) {
            throw new IllegalArgumentException("Too many edges for brute force: " + m);
        }
        int best = -1;
        for (int mask = 0; mask < (1 << m); mask++) {
            int cost = 0;
            boolean allowed = true;
            for (int i = 0; i < m && allowed; i++) {
                if (((mask >> i) & 1) != 0) {
                    int cap = edges.get(i)[2];
                    if (cap >= unremovableAtLeast) {
                        allowed = false;
                    }
                    cost += cap;
                }
            }
            if (!allowed || (best >= 0 && cost >= best)) {
                continue;
            }
            if (!connected(net.size(), edges, mask, s, t)) {
                best = cost;
            }
        }
        return best;
    }

    private static boolean connected(int n, List<int[]> edges, int removedMask, int s, int t) {
        boolean[] seen = new boolean[n];
        seen[s] = true;
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int i = 0; i < edges.size(); i++) {
                if (((removedMask >> i) & 1) != 0) {
                    continue;
                }
                int[] e = edges.get(i);
                if (seen[e[0]] && !seen[e[1]]) {
                    seen[e[1]] = true;
                    changed = true;
                }
            }
        }
        return seen[t];
    }
}
