package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlan;
import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.FordFulkerson;
import com.breachpath.graph.MaxFlowAlgorithm;
import com.breachpath.model.Asset;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import java.util.List;
import org.junit.jupiter.api.Test;

class ContainmentPlannerTest {

    /** A(0) -> B(1) -> D(3) and A(0) -> C(2) -> D(3); hosts B and C cost 5 to isolate. */
    private static Topology diamond() {
        List<Asset> assets = List.of(
                new Asset("A", "workstation", 1),
                new Asset("B", "server", 5),
                new Asset("C", "server", 5),
                new Asset("D", "database", 100));
        List<Link> links = List.of(
                new Link(0, 1, 10, true),
                new Link(0, 2, 10, true),
                new Link(1, 3, 10, true),
                new Link(2, 3, 10, true));
        return new Topology(assets, links);
    }

    @Test
    void prefersCheapHostIsolationOverExpensiveLinks() {
        for (MaxFlowAlgorithm algo : new MaxFlowAlgorithm[]{new EdmondsKarp(), new FordFulkerson()}) {
            ContainmentPlan p = new ContainmentPlanner().plan(diamond(), List.of(0), List.of(3), false, algo);
            assertTrue(p.feasible());
            assertEquals(10, p.totalCost());
            assertEquals(2, p.actions().size());
            assertTrue(p.actions().stream().allMatch(a -> a.type().equals("ISOLATE_HOST")));
            assertTrue(p.verified());
        }
    }

    @Test
    void allowingSourceIsolationIsCheaper() {
        ContainmentPlan p = new ContainmentPlanner().plan(diamond(), List.of(0), List.of(3), true, new EdmondsKarp());
        assertEquals(1, p.totalCost());
        assertEquals(1, p.actions().size());
        assertTrue(p.verified());
    }

    @Test
    void unreachableTargetCostsNothing() {
        Topology t = new Topology(
                List.of(new Asset("A", "ws", 1), new Asset("B", "db", 100)),
                List.of());
        ContainmentPlan p = new ContainmentPlanner().plan(t, List.of(0), List.of(1), false, new EdmondsKarp());
        assertTrue(p.feasible());
        assertEquals(0, p.totalCost());
        assertTrue(p.actions().isEmpty());
        assertTrue(p.verified());
    }

    @Test
    void directedLinkOnlyBlocksOneDirection() {
        Topology t = new Topology(
                List.of(new Asset("A", "ws", 1), new Asset("B", "db", 100)),
                List.of(new Link(0, 1, 7, false)));
        ContainmentPlan p = new ContainmentPlanner().plan(t, List.of(0), List.of(1), false, new EdmondsKarp());
        assertEquals(7, p.totalCost());
        assertEquals("BLOCK_LINK", p.actions().get(0).type());
    }

    @Test
    void rejectsHostThatIsBothSourceAndTarget() {
        assertThrows(IllegalArgumentException.class,
                () -> new ContainmentPlanner().plan(diamond(), List.of(0), List.of(0), false, new EdmondsKarp()));
    }
}
