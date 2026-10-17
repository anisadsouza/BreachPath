package com.breachpath.graph;

import java.util.Arrays;

/** Edmonds-Karp: Ford-Fulkerson where every augmenting path is the shortest one, found by BFS. */
public class EdmondsKarp implements MaxFlowAlgorithm {

    @Override
    public String name() {
        return "Edmonds-Karp (BFS)";
    }

    @Override
    public MaxFlowResult compute(FlowNetwork net, int s, int t) {
        MinCut.checkEndpoints(net, s, t);
        long start = System.nanoTime();
        int n = net.size();
        int[][] r = net.copyCapacity();
        int[] parent = new int[n];
        int[] queue = new int[n];
        int flow = 0;

        while (true) {
            Arrays.fill(parent, -1);
            parent[s] = s;
            int head = 0;
            int tail = 0;
            queue[tail++] = s;
            while (head < tail && parent[t] == -1) {
                int u = queue[head++];
                for (int v = 0; v < n; v++) {
                    if (parent[v] == -1 && r[u][v] > 0) {
                        parent[v] = u;
                        queue[tail++] = v;
                    }
                }
            }
            if (parent[t] == -1) {
                break;
            }
            int bottleneck = Integer.MAX_VALUE;
            for (int v = t; v != s; v = parent[v]) {
                bottleneck = Math.min(bottleneck, r[parent[v]][v]);
            }
            for (int v = t; v != s; v = parent[v]) {
                r[parent[v]][v] -= bottleneck;
                r[v][parent[v]] += bottleneck;
            }
            flow += bottleneck;
        }
        return MinCut.build(name(), net, r, s, flow, System.nanoTime() - start);
    }
}
