package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlan;
import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.IocEngine;
import com.breachpath.model.Asset;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import com.breachpath.ui.DashboardModel;
import com.breachpath.ui.DashboardModel.Scenario;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Editing a link cost in a running session: the plans update, everything else stays. */
class DashboardLinkCostTest {
    private static final int INF = ContainmentPlanner.INF;
    private DashboardModel model;

    @BeforeEach
    void load() throws IOException {
        model = DashboardModel.load(Path.of("data"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
    }

    @Test
    void raisingTheCostOfACutLinkMakesThePlanChooseAnotherCut() {
        assertEquals(18, model.plan(Scenario.STRICT).totalCost());
        model.setLinkCost(0, 100); // WS-Alice to WEB-01
        ContainmentPlan a = model.plan(Scenario.STRICT);
        assertEquals(23, a.totalCost());
        assertTrue(a.verified());
        List<String> actions = a.actions().stream().map(ContainmentPlan.Action::description).toList();
        assertTrue(actions.contains("Block link WS-Alice -> FILE-01"));
        assertTrue(actions.contains("Block link WEB-01 -> APP-01"));
        assertEquals(5, model.plan(Scenario.RELAXED).totalCost(), "isolating the host is still the cheapest");
    }

    @Test
    void loweringACostLowersTheCut() {
        model.setLinkCost(0, 0);
        assertEquals(8, model.plan(Scenario.STRICT).totalCost());
    }

    @Test
    void anEditedModelAgreesWithAFreshModelBuiltWithThoseCosts() {
        Random rnd = new Random(5);
        List<Link> links = new ArrayList<>(model.links());
        for (int round = 0; round < 25; round++) {
            int index = rnd.nextInt(links.size());
            int cost = rnd.nextInt(5) == 0 ? INF : rnd.nextInt(60);
            model.setLinkCost(index, cost);
            Link old = links.get(index);
            links.set(index, new Link(old.from(), old.to(), cost, old.bidirectional()));

            DashboardModel fresh = new DashboardModel(new Topology(model.topology().assets(), links), List.of(),
                    IocEngine.fromLines(List.of()), List.of());
            fresh.analyse("WS-Alice", "DB-PROD", 0, 23);
            for (Scenario s : new Scenario[]{Scenario.STRICT, Scenario.RELAXED}) {
                ContainmentPlan edited = model.plan(s);
                ContainmentPlan expected = fresh.plan(s);
                assertEquals(expected.feasible(), edited.feasible(), "round " + round);
                assertEquals(expected.totalCost(), edited.totalCost(), "round " + round);
                if (edited.feasible()) {
                    assertTrue(edited.verified(), "round " + round);
                }
            }
        }
    }

    @Test
    void anUncuttableLinkCanMakeContainmentImpossibleWithoutIsolation() {
        Topology topo = new Topology(
                List.of(new Asset("X", "server", 9), new Asset("T", "database", 100)),
                List.of(new Link(0, 1, 5, false)));
        DashboardModel small = new DashboardModel(topo, List.of(), IocEngine.fromLines(List.of()), List.of());
        small.analyse("X", "T", 0, 23);
        assertEquals(5, small.plan(Scenario.STRICT).totalCost());

        small.setLinkCost(0, INF);
        assertFalse(small.plan(Scenario.STRICT).feasible());
        assertTrue(small.plan(Scenario.RELAXED).feasible());
        assertEquals(9, small.plan(Scenario.RELAXED).totalCost(), "isolating X is the only way out");
        assertEquals("never cut", DashboardModel.costText(small.links().get(0).cost()));
    }

    @Test
    void badEditsAreRejectedAndChangeNothing() {
        assertThrows(IllegalArgumentException.class, () -> model.setLinkCost(0, -1));
        assertThrows(IllegalArgumentException.class, () -> model.setLinkCost(0, INF + 1));
        assertThrows(IllegalArgumentException.class, () -> model.setLinkCost(-1, 5));
        assertThrows(IllegalArgumentException.class, () -> model.setLinkCost(model.links().size(), 5));
        assertTrue(model.costChanges().isEmpty());
        assertEquals(18, model.plan(Scenario.STRICT).totalCost());
    }

    @Test
    void resetPutsEveryCostBack() {
        model.setLinkCost(0, 100);
        model.setLinkCost(3, 1);
        assertEquals(2, model.costChanges().size());
        model.resetLinkCosts();
        assertTrue(model.costChanges().isEmpty());
        assertEquals(18, model.plan(Scenario.STRICT).totalCost());
        assertEquals(10, model.links().get(0).cost());
    }

    @Test
    void incidentsAndEvidenceSurviveACostEdit() {
        model.addEvidence("DB-PROD", 12, 30);
        assertEquals(36, model.incidentFor("DB-PROD").riskScore());
        int incidents = model.ranked().size();
        model.setLinkCost(0, 100);
        assertEquals(36, model.incidentFor("DB-PROD").riskScore());
        assertEquals(incidents, model.ranked().size());
        assertTrue(model.isBalanced());
    }

    @Test
    void whatIfFollowsTheNewCosts() {
        DashboardModel.WhatIfRow before = model.whatIf().stream()
                .filter(r -> r.host().equals("WS-Alice")).findFirst().orElseThrow();
        assertEquals(18, before.costA());
        model.setLinkCost(0, 100);
        DashboardModel.WhatIfRow after = model.whatIf().stream()
                .filter(r -> r.host().equals("WS-Alice")).findFirst().orElseThrow();
        assertEquals(23, after.costA());
    }

    @Test
    void changesAreListedInPlainWords() {
        model.setLinkCost(0, 100);
        model.setLinkCost(1, INF);
        assertEquals(List.of("WS-Alice to WEB-01: 10 to 100", "WS-Alice to FILE-01: 8 to never cut"),
                model.costChanges());
        model.setLinkCost(0, 10);
        assertEquals(List.of("WS-Alice to FILE-01: 8 to never cut"), model.costChanges(),
                "a cost put back to its original value is not a change");
    }

    @Test
    void editsAndResetsNeedAnAnalysisFirst() throws IOException {
        DashboardModel fresh = DashboardModel.load(Path.of("data"));
        assertThrows(IllegalStateException.class, () -> fresh.setLinkCost(0, 5));
        assertThrows(IllegalStateException.class, fresh::resetLinkCosts);
    }

    @Test
    void costAndPriorityLabels() {
        assertEquals("5", DashboardModel.costText(5));
        assertEquals("never cut", DashboardModel.costText(INF));
        assertEquals("Low", DashboardModel.priority(29));
        assertEquals("Medium", DashboardModel.priority(30));
        assertEquals("Medium", DashboardModel.priority(59));
        assertEquals("High", DashboardModel.priority(60));
        assertEquals("High", DashboardModel.priority(79));
        assertEquals("Critical", DashboardModel.priority(80));
        assertEquals("Critical", DashboardModel.priority(100));
    }
}