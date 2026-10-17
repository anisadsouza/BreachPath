package com.breachpath.graph;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** Extracts the minimum cut from a final residual graph. */
final class MinCut {
    private MinCut() {
    }

    static MaxFlowResult build(String name, FlowNetwork net, int[][] residual,
                               int source, int flow, long nanos) {
        int n = net.size();
        boolean[] side = new boolean[n];
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        side[source] = true;
        queue.add(source);
        while (!queue.isEmpty()) {
            int u = queue.poll();
            for (int v = 0; v < n; v++) {
                if (!side[v] && residual[u][v] > 0) {
                    side[v] = true;
                    queue.add(v);
                }
            }
        }
        List<int[]> cut = new ArrayList<>();
        for (int[] e : net.edges()) {
            if (side[e[0]] && !side[e[1]]) {
                cut.add(e.clone());
            }
        }
        return new MaxFlowResult(name, flow, side, cut, nanos);
    }

    static void checkEndpoints(FlowNetwork net, int s, int t) {
        if (s == t || s < 0 || t < 0 || s >= net.size() || t >= net.size()) {
            throw new IllegalArgumentException("Invalid source/sink: " + s + ", " + t);
        }
    }
}
