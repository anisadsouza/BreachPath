package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlan;
import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.EventTimeline;
import com.breachpath.engine.IncidentIndex;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.MaxFlowAlgorithm;
import com.breachpath.model.Asset;
import com.breachpath.model.Incident;
import com.breachpath.model.Link;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
import com.breachpath.storage.DataLoader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Corner cases from the project specification: multiple hosts, uncuttable paths, repeated updates, bad input. */
class CornerCaseTest {

    /** A(0) and B(1) -> C(2) -> D(3) target; E(4) is a second target behind C. */
    private static Topology funnel() {
        List<Asset> assets = List.of(
                new Asset("A", "workstation", 50),
                new Asset("B", "workstation", 50),
                new Asset("C", "server", 7),
                new Asset("D", "database", 100),
                new Asset("E", "admin", 100));
        List<Link> links = List.of(
                new Link(0, 2, 20, false),
                new Link(1, 2, 20, false),
                new Link(2, 3, 20, false),
                new Link(2, 4, 20, false));
        return new Topology(assets, links);
    }

    // ---- containment ------------------------------------------------------------------------

    @Test
    void multipleCompromisedHostsAreAllCutOffByOneCheapIsolation() {
        for (MaxFlowAlgorithm algo : new MaxFlowAlgorithm[]{new EdmondsKarp()}) {
            ContainmentPlan p = new ContainmentPlanner().plan(funnel(), List.of(0, 1), List.of(3), false, algo);
            assertTrue(p.feasible());
            assertEquals(7, p.totalCost(), algo.name());
            assertEquals(1, p.actions().size());
            assertEquals("Isolate host C", p.actions().get(0).description());
            assertTrue(p.verified());
        }
    }

    @Test
    void multipleTargetsAreAllProtected() {
        ContainmentPlan p = new ContainmentPlanner().plan(funnel(), List.of(0, 1), List.of(3, 4), false,
                new EdmondsKarp());
        assertTrue(p.feasible());
        assertEquals(7, p.totalCost());
        assertTrue(p.verified());
    }

    @Test
    void uncuttablePathMeansNoFiniteContainment() {
        List<Asset> assets = List.of(new Asset("A", "workstation", 1), new Asset("B", "database", 100));
        List<Link> links = List.of(new Link(0, 1, ContainmentPlanner.INF, false));
        for (MaxFlowAlgorithm algo : new MaxFlowAlgorithm[]{new EdmondsKarp()}) {
            ContainmentPlan strict = new ContainmentPlanner().plan(new Topology(assets, links), List.of(0),
                    List.of(1), false, algo);
            assertFalse(strict.feasible());
            assertTrue(strict.actions().isEmpty());
            assertFalse(strict.verified());

            // Isolating the compromised host itself is the only way out, and it is cheap.
            ContainmentPlan relaxed = new ContainmentPlanner().plan(new Topology(assets, links), List.of(0),
                    List.of(1), true, algo);
            assertTrue(relaxed.feasible());
            assertEquals(1, relaxed.totalCost());
            assertTrue(relaxed.verified());
        }
    }

    @Test
    void needsAtLeastOneSourceAndOneTarget() {
        ContainmentPlanner planner = new ContainmentPlanner();
        assertThrows(IllegalArgumentException.class,
                () -> planner.plan(funnel(), List.of(), List.of(3), false, new EdmondsKarp()));
        assertThrows(IllegalArgumentException.class,
                () -> planner.plan(funnel(), List.of(0), List.of(), false, new EdmondsKarp()));
    }

    // ---- incident index ---------------------------------------------------------------------

    @Test
    void repeatedUpdatesOfOneIncidentKeepTheTreeValid() {
        IncidentIndex index = new IncidentIndex();
        Incident a = index.open("A", 10, List.of("start"));
        index.open("B", 50, List.of("start"));
        index.open("C", 50, List.of("start"));
        for (int i = 0; i < 100; i++) {
            int score = (i % 2 == 0) ? 90 : 5;
            assertTrue(index.updateScore(a.id(), score, "update " + i));
            assertTrue(index.isBalanced());
            assertEquals(3, index.size());
            assertEquals(score == 90 ? "A" : "B", index.top(1).get(0).host());
        }
        assertEquals(101, index.find(a.id()).reasons().size());
    }

    @Test
    void unknownIncidentIdsAreHandledGracefully() {
        IncidentIndex index = new IncidentIndex();
        assertFalse(index.updateScore(42, 10, "x"));
        assertFalse(index.close(42));
        assertNull(index.find(42));
        assertTrue(index.top(5).isEmpty());
        assertTrue(index.isBalanced());
    }

    @Test
    void emptyIndexAfterClosingEverything() {
        IncidentIndex index = new IncidentIndex();
        Incident a = index.open("A", 1, List.of());
        Incident b = index.open("B", 1, List.of());
        assertTrue(index.close(a.id()));
        assertTrue(index.close(b.id()));
        assertEquals(0, index.size());
        assertTrue(index.isBalanced());
    }

    // ---- timeline ---------------------------------------------------------------------------

    @Test
    void timelineRejectsBadWindowsAndHours() {
        EventTimeline t = new EventTimeline(
                List.of(new SecurityEvent(3, "A", "X", 4, "", "")), 24);
        assertThrows(IllegalArgumentException.class, () -> t.total("A", 5, 2));
        assertThrows(IllegalArgumentException.class, () -> t.total("A", -1, 2));
        assertThrows(IllegalArgumentException.class, () -> t.peak("A", 0, 24));
        assertThrows(IllegalArgumentException.class, () -> t.addAlerts("A", 24, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new EventTimeline(List.of(new SecurityEvent(-1, "A", "X", 1, "", "")), 24));
    }

    @Test
    void timelineRepeatedUpdatesAccumulateAndUnknownHostsAreZero() {
        EventTimeline t = new EventTimeline(List.of(new SecurityEvent(3, "A", "X", 4, "", "")), 24);
        for (int i = 0; i < 10; i++) {
            t.addAlerts("A", 3, 5);
        }
        assertEquals(54, t.total("A", 0, 23));
        assertEquals(54, t.peak("A", 3, 3));
        assertEquals(0, t.total("ghost", 0, 23));
        t.addAlerts("new-host", 7, 2);
        assertEquals(2, t.total("new-host", 0, 23));
    }

    // ---- data loading -----------------------------------------------------------------------

    private static Path write(Path dir, String name, String content) throws IOException {
        return Files.writeString(dir.resolve(name), content);
    }

    @Test
    void loaderRejectsRowsWithWrongColumnCount(@TempDir Path dir) throws IOException {
        Path assets = write(dir, "assets.csv", "name,type,isolationCost\nA,workstation\n");
        Path edges = write(dir, "edges.csv", "from,to,cost,bidirectional\n");
        assertThrows(IllegalArgumentException.class, () -> DataLoader.loadTopology(assets, edges));
    }

    @Test
    void loaderRejectsEdgesToUnknownAssetsAndDuplicateAssets(@TempDir Path dir) throws IOException {
        Path assets = write(dir, "assets.csv", "name,type,isolationCost\nA,workstation,1\nB,server,2\n");
        Path badEdges = write(dir, "bad.csv", "from,to,cost,bidirectional\nA,Z,3,true\n");
        assertThrows(IllegalArgumentException.class, () -> DataLoader.loadTopology(assets, badEdges));

        Path dupAssets = write(dir, "dup.csv", "name,type,isolationCost\nA,workstation,1\nA,server,2\n");
        Path edges = write(dir, "ok.csv", "from,to,cost,bidirectional\n");
        assertThrows(IllegalArgumentException.class, () -> DataLoader.loadTopology(dupAssets, edges));
    }

    @Test
    void loaderIgnoresCommentsAndBlankLines(@TempDir Path dir) throws IOException {
        Path assets = write(dir, "assets.csv", "name,type,isolationCost\n# comment\n\nA,workstation,1\nB,server,2\n");
        Path edges = write(dir, "edges.csv", "from,to,cost,bidirectional\nA,B,3,true\n");
        Topology topo = DataLoader.loadTopology(assets, edges);
        assertEquals(2, topo.size());
        assertEquals(1, topo.links().size());
    }

    @Test
    void emptyEventFileGivesEmptyList(@TempDir Path dir) throws IOException {
        Path events = write(dir, "events.csv", "hour,host,eventType,count,indicator,command\n");
        assertTrue(DataLoader.loadEvents(events).isEmpty());
    }
}