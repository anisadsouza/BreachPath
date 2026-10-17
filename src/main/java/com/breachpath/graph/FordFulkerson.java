package com.breachpath.graph;

import java.util.Arrays;

/** Ford-Fulkerson with depth-first search for augmenting paths (used as a benchmark baseline). */
public class FordFulkerson implements MaxFlowAlgorithm {

    @Override
    public String name() {
        return "Ford-Fulkerson (DFS)";
    }

    @Override
    public MaxFlowResult compute(FlowNetwork net, int s, int t) {
        MinCut.checkEndpoints(net, s, t);
        long start = System.nanoTime();
        int n = net.size();
        int[][] r = net.copyCapacity();
        boolean[] seen = new boolean[n];
        int flow = 0;
        while (true) {
            Arrays.fill(seen, false);
            int pushed = dfs(r, seen, s, t, Integer.MAX_VALUE);
            if (pushed == 0) {
                break;
            }
            flow += pushed;
        }
        return MinCut.build(name(), net, r, s, flow, System.nanoTime() - start);
    }

    private int dfs(int[][] r, boolean[] seen, int u, int t, int pushed) {
        if (u == t) {
            return pushed;
        }
        seen[u] = true;
        for (int v = 0; v < r.length; v++) {
            if (!seen[v] && r[u][v] > 0) {
                int d = dfs(r, seen, v, t, Math.min(pushed, r[u][v]));
                if (d > 0) {
                    r[u][v] -= d;
                    r[v][u] += d;
                    return d;
                }
            }
        }
        return 0;
    }
}
