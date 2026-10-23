package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.breachpath.graph.BruteForceMinCut;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.FlowNetwork;
import com.breachpath.graph.MaxFlowAlgorithm;
import com.breachpath.graph.MaxFlowResult;
import java.util.Random;
import org.junit.jupiter.api.Test;

class MaxFlowTest {
    private final MaxFlowAlgorithm[] algorithms = {new EdmondsKarp()};

    private static FlowNetwork textbookNetwork() {
        FlowNetwork net = new FlowNetwork(6);
        net.addEdge(0, 1, 16);
        net.addEdge(0, 2, 13);
        net.addEdge(1, 2, 10);
        net.addEdge(2, 1, 4);
        net.addEdge(1, 3, 12);
        net.addEdge(3, 2, 9);
        net.addEdge(2, 4, 14);
        net.addEdge(4, 3, 7);
        net.addEdge(3, 5, 20);
        net.addEdge(4, 5, 4);
        return net;
    }

    @Test
    void textbookGraphHasMaxFlow23() {
        for (MaxFlowAlgorithm a : algorithms) {
            MaxFlowResult r = a.compute(textbookNetwork(), 0, 5);
            assertEquals(23, r.maxFlow());
            assertEquals(23, r.cutCost());
        }
    }

    @Test
    void disconnectedGraphHasZeroFlowAndEmptyCut() {
        FlowNetwork net = new FlowNetwork(4);
        net.addEdge(0, 1, 5);
        net.addEdge(2, 3, 5);
        for (MaxFlowAlgorithm a : algorithms) {
            MaxFlowResult r = a.compute(net, 0, 3);
            assertEquals(0, r.maxFlow());
            assertEquals(0, r.cutCost());
        }
    }

    @Test
    void cutSeparatesSourceFromSink() {
        for (MaxFlowAlgorithm a : algorithms) {
            MaxFlowResult r = a.compute(textbookNetwork(), 0, 5);
            assertEquals(true, r.sourceSide()[0]);
            assertEquals(false, r.sourceSide()[5]);
        }
    }

    @Test
    void invalidEndpointsAreRejected() {
        FlowNetwork net = new FlowNetwork(3);
        assertThrows(IllegalArgumentException.class, () -> new EdmondsKarp().compute(net, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new EdmondsKarp().compute(net, 0, 7));
    }

    @Test
    void bothAlgorithmsMatchBruteForceOnRandomSmallGraphs() {
        Random rnd = new Random(31);
        for (int trial = 0; trial < 150; trial++) {
            int n = 6;
            FlowNetwork net = new FlowNetwork(n);
            int m = 6 + rnd.nextInt(8);
            for (int i = 0; i < m; i++) {
                int u = rnd.nextInt(n);
                int v = rnd.nextInt(n);
                if (u != v) {
                    net.addEdge(u, v, 1 + rnd.nextInt(9));
                }
            }
            int expected = BruteForceMinCut.minCutCost(net, 0, n - 1, Integer.MAX_VALUE);
            for (MaxFlowAlgorithm a : algorithms) {
                MaxFlowResult r = a.compute(net, 0, n - 1);
                assertEquals(expected, r.maxFlow());
                assertEquals(expected, r.cutCost());
            }
        }
    }
}
