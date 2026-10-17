package com.breachpath.graph;

import java.util.List;

/**
 * Result of a max-flow run.
 *
 * @param sourceSide which vertices are still reachable from the source in the residual graph
 * @param cutEdges   the minimum cut, as {u, v, capacity} edges from the source side to the sink side
 */
public record MaxFlowResult(String algorithm, int maxFlow, boolean[] sourceSide,
                            List<int[]> cutEdges, long nanos) {

    public int cutCost() {
        int total = 0;
        for (int[] e : cutEdges) {
            total += e[2];
        }
        return total;
    }
}
