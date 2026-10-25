package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.IocEngine;
import com.breachpath.model.Asset;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import com.breachpath.ui.DashboardModel;
import com.breachpath.ui.DashboardModel.WhatIfRow;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The what-if sweep: treat each host in turn as the only compromised one. */
class DashboardWhatIfTest {

    private static DashboardModel sample(String compromised, String targets) throws IOException {
        DashboardModel model = DashboardModel.load(Path.of("data"));
        model.analyse(compromised, targets, 0, 23);
        return model;
    }

    @Test
    void everyOtherHostIsSweptAndTheTargetIsLeftOut() throws IOException {
        List<WhatIfRow> rows = sample("WS-Alice", "DB-PROD").whatIf();
        assertEquals(11, rows.size());
        assertTrue(rows.stream().noneMatch(r -> r.host().equals("DB-PROD")));
    }

    @Test
    void aliceMatchesTheContainmentTab() throws IOException {
        WhatIfRow alice = sample("WS-Alice", "DB-PROD").whatIf().stream()
                .filter(r -> r.host().equals("WS-Alice")).findFirst().orElseThrow();
        assertTrue(alice.reaches());
        assertEquals(3, alice.hops());
        assertEquals(18, alice.costA());
        assertEquals(5, alice.costB());
    }

    @Test
    void allowingIsolationNeverCostsMore() throws IOException {
        for (WhatIfRow r : sample("WS-Alice", "DB-PROD,CLOUD-ADMIN").whatIf()) {
            if (r.reaches() && r.feasibleA() && r.feasibleB()) {
                assertTrue(r.costB() <= r.costA(), r.host());
            }
        }
    }

    @Test
    void hardestToContainComesFirst() throws IOException {
        List<WhatIfRow> rows = sample("WS-Alice", "DB-PROD").whatIf();
        for (int i = 1; i < rows.size(); i++) {
            assertTrue(rows.get(i - 1).costA() >= rows.get(i).costA());
        }
        assertEquals("APP-01", rows.get(0).host());
    }

    @Test
    void severalTargetsAreAllExcluded() throws IOException {
        List<WhatIfRow> rows = sample("WS-Alice", "DB-PROD,CLOUD-ADMIN").whatIf();
        assertEquals(10, rows.size());
        assertTrue(rows.stream().noneMatch(r -> r.host().equals("CLOUD-ADMIN")));
    }

    @Test
    void sweepDoesNotDependOnWhichHostIsCurrentlyCompromised() throws IOException {
        assertEquals(sample("WS-Alice", "DB-PROD").whatIf(), sample("WS-Bob", "DB-PROD").whatIf());
    }

    @Test
    void needsAnalysisFirst() throws IOException {
        DashboardModel fresh = DashboardModel.load(Path.of("data"));
        assertThrows(IllegalStateException.class, fresh::whatIf);
    }

    @Test
    void unreachableAndUncuttableHostsAreReportedHonestly() {
        // X -> T over a link that can never be cut; Y has no links at all.
        Topology topo = new Topology(
                List.of(new Asset("X", "server", 9), new Asset("T", "database", 100), new Asset("Y", "server", 4)),
                List.of(new Link(0, 1, ContainmentPlanner.INF, false)));
        DashboardModel model = new DashboardModel(topo, List.of(), IocEngine.fromLines(List.of()), List.of());
        model.analyse("X", "T", 0, 23);
        List<WhatIfRow> rows = model.whatIf();
        assertEquals(2, rows.size());

        WhatIfRow x = rows.get(0);
        assertEquals("X", x.host());
        assertTrue(x.reaches());
        assertEquals(1, x.hops());
        assertFalse(x.feasibleA(), "an uncuttable link cannot be contained while X stays online");
        assertTrue(x.feasibleB());
        assertEquals(9, x.costB(), "isolating X itself is the only way out");

        WhatIfRow y = rows.get(1);
        assertEquals("Y", y.host());
        assertFalse(y.reaches());
        assertEquals(0, y.hops());
    }
}