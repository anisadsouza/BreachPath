package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlan;
import com.breachpath.model.Incident;
import com.breachpath.ui.DashboardModel;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Headless tests for the logic behind the JavaFX dashboard (uses the real data/ directory). */
class DashboardModelTest {
    private DashboardModel model;

    @BeforeEach
    void load() throws IOException {
        model = DashboardModel.load(Path.of("data"));
    }

    private int idx(String host) {
        return model.topology().indexOf(host);
    }

    @Test
    void mustAnalyseBeforeReading() {
        assertFalse(model.isAnalysed());
        assertThrows(IllegalStateException.class, () -> model.ranked());
        assertThrows(IllegalStateException.class, () -> model.addEvidence("WS-Alice", 1, 1));
    }

    @Test
    void defaultScenarioRanksAliceFirstAndTreeIsBalanced() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        List<Incident> ranked = model.ranked();
        assertEquals(11, ranked.size());
        assertEquals("WS-Alice", ranked.get(0).host());
        for (int i = 1; i < ranked.size(); i++) {
            assertTrue(ranked.get(i - 1).riskScore() >= ranked.get(i).riskScore());
        }
        assertTrue(model.isBalanced());
        assertEquals(List.of(List.of(idx("WS-Alice"), idx("WEB-01"), idx("APP-01"), idx("DB-PROD"))),
                model.attackPaths());
    }

    @Test
    void containmentScenariosMatchConsoleReport() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        ContainmentPlan strict = model.plan(DashboardModel.Scenario.STRICT);
        ContainmentPlan relaxed = model.plan(DashboardModel.Scenario.RELAXED);
        assertEquals(18, strict.totalCost());
        assertEquals(5, relaxed.totalCost());
        assertTrue(strict.verified());
        assertTrue(relaxed.verified());
        assertNull(model.plan(DashboardModel.Scenario.NONE));

        List<int[]> blocked = model.blockedLinks(strict);
        assertEquals(2, blocked.size());
        for (int[] b : blocked) {
            assertEquals(idx("WS-Alice"), b[0]);
            assertTrue(b[1] == idx("WEB-01") || b[1] == idx("FILE-01"));
        }
        assertTrue(model.isolatedHosts(strict).isEmpty());
        assertEquals(Set.of(idx("WS-Alice")), model.isolatedHosts(relaxed));
        assertTrue(model.blockedLinks(relaxed).isEmpty());
        assertTrue(model.blockedLinks(null).isEmpty());
    }

    @Test
    void addingEvidenceMovesTheIncidentUpTheQueue() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        Incident before = model.incidentFor("DB-PROD");
        assertEquals(6, before.riskScore());
        Incident after = model.addEvidence("DB-PROD", 12, 30);
        assertEquals(36, after.riskScore());
        assertEquals(before.id(), after.id());
        assertTrue(model.isBalanced());
        assertEquals(11, model.ranked().size());
        int rank = 0;
        for (Incident i : model.ranked()) {
            if (i.host().equals("DB-PROD")) {
                break;
            }
            rank++;
        }
        assertTrue(rank < 10, "DB-PROD should no longer be last");
        assertEquals(30, model.hourly("DB-PROD")[12]);
    }

    @Test
    void repeatedEvidenceKeepsTreeBalanced() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        for (int i = 0; i < 40; i++) {
            model.addEvidence("WS-Carol", i % 24, 3);
            assertTrue(model.isBalanced());
        }
        assertEquals(11, model.ranked().size());
    }

    @Test
    void evidenceForHostWithoutIncidentOpensOne() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        assertNull(model.incidentFor("CLOUD-ADMIN"));
        Incident inc = model.addEvidence("CLOUD-ADMIN", 5, 10);
        assertNotNull(inc);
        assertEquals(12, model.ranked().size());
        assertTrue(model.isBalanced());
    }

    @Test
    void analyseAgainResetsEvidence() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        model.addEvidence("DB-PROD", 12, 30);
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        assertEquals(6, model.incidentFor("DB-PROD").riskScore());
        assertNull(model.incidentFor("CLOUD-ADMIN"));
    }

    @Test
    void windowChangesTheQueriedTotals() {
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        int all = model.windowTotal("WS-Alice");
        model.analyse("WS-Alice", "DB-PROD", 0, 1);
        assertTrue(model.windowTotal("WS-Alice") < all);
        assertEquals(model.hourly("WS-Alice")[0] + model.hourly("WS-Alice")[1], model.windowTotal("WS-Alice"));
    }

    @Test
    void multipleCompromisedHostsAndTargets() {
        model.analyse("WS-Alice,WS-Bob", "DB-PROD,CLOUD-ADMIN", 0, 23);
        assertEquals(2, model.sources().size());
        assertEquals(2, model.targets().size());
        ContainmentPlan p = model.plan(DashboardModel.Scenario.STRICT);
        if (p.feasible()) {
            assertTrue(p.verified());
        }
        ContainmentPlan relaxed = model.plan(DashboardModel.Scenario.RELAXED);
        if (relaxed.feasible()) {
            assertTrue(relaxed.verified());
        }
    }

    @Test
    void badInputIsRejectedWithClearErrors() {
        assertThrows(IllegalArgumentException.class, () -> model.analyse("Nobody", "DB-PROD", 0, 23));
        assertThrows(IllegalArgumentException.class, () -> model.analyse("WS-Alice", "Nowhere", 0, 23));
        assertThrows(IllegalArgumentException.class, () -> model.analyse("DB-PROD", "DB-PROD", 0, 23));
        assertThrows(IllegalArgumentException.class, () -> model.analyse("WS-Alice", "DB-PROD", 10, 5));
        assertThrows(IllegalArgumentException.class, () -> model.analyse("WS-Alice", "DB-PROD", 0, 24));
        assertThrows(IllegalArgumentException.class, () -> model.analyse("", "DB-PROD", 0, 23));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        assertThrows(IllegalArgumentException.class, () -> model.addEvidence("Ghost", 1, 1));
    }
}
