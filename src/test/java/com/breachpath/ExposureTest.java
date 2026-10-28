package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.EventTimeline;
import com.breachpath.engine.RiskAssessment;
import com.breachpath.engine.RiskScorer;
import com.breachpath.engine.IocEngine;
import com.breachpath.model.Asset;
import com.breachpath.model.Incident;
import com.breachpath.model.Link;
import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
import com.breachpath.storage.DataLoader;
import com.breachpath.ui.DashboardModel;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Internet-facing and patch status: the data file, the risk score and the what-if ranking. */
class ExposureTest {

    private static final String EDGES = "from,to,cost,bidirectional\n";

    private static Topology load(Path dir, String assetRows) throws IOException {
        Path assets = Files.writeString(dir.resolve("assets.csv"), assetRows);
        Path edges = Files.writeString(dir.resolve("edges.csv"), EDGES);
        return DataLoader.loadTopology(assets, edges);
    }

    // ---- the asset ---------------------------------------------------------------------------

    @Test
    void threeArgumentAssetIsInternalAndPatched() {
        Asset a = new Asset("A", "server", 5);
        assertFalse(a.internetFacing());
        assertTrue(a.patched());
        assertFalse(a.exposedAndUnpatched());
        assertTrue(new Asset("B", "server", 5, true, false).exposedAndUnpatched());
        assertFalse(new Asset("C", "server", 5, true, true).exposedAndUnpatched());
        assertFalse(new Asset("D", "server", 5, false, false).exposedAndUnpatched());
    }

    // ---- the data file -----------------------------------------------------------------------

    @Test
    void oldThreeColumnFilesStillLoadWithSafeDefaults(@TempDir Path dir) throws IOException {
        Topology topo = load(dir, "name,type,isolationCost\nA,workstation,1\nB,server,2\n");
        assertFalse(topo.asset(0).internetFacing());
        assertTrue(topo.asset(0).patched());
    }

    @Test
    void fiveColumnFilesCarryTheFlags(@TempDir Path dir) throws IOException {
        Topology topo = load(dir, "name,type,isolationCost,internetFacing,patched\n"
                + "A,server,1,true,false\nB,server,2,false,true\nC,server,3,YES,no\nD,server,4,1,0\nE,server,5,false,true\n");
        assertTrue(topo.asset(0).exposedAndUnpatched());
        assertFalse(topo.asset(1).internetFacing());
        assertTrue(topo.asset(2).exposedAndUnpatched(), "yes/no are accepted in any case");
        assertTrue(topo.asset(3).exposedAndUnpatched(), "1/0 are accepted");
        assertTrue(topo.asset(4).patched());
    }

    @Test
    void mixedThreeAndFiveColumnRowsAreFine(@TempDir Path dir) throws IOException {
        Topology topo = load(dir, "name,type,isolationCost,internetFacing,patched\nA,server,1\nB,server,2,true,false\n");
        assertTrue(topo.asset(0).patched());
        assertTrue(topo.asset(1).exposedAndUnpatched());
    }

    @Test
    void fourColumnsAndBadFlagsAreRejectedWithAClearMessage(@TempDir Path dir) {
        IllegalArgumentException four = assertThrows(IllegalArgumentException.class,
                () -> load(dir, "name,type,isolationCost,internetFacing\nA,server,1,true\n"));
        assertTrue(four.getMessage().contains("A"), four.getMessage());
        IllegalArgumentException bad = assertThrows(IllegalArgumentException.class,
                () -> load(dir, "name,type,isolationCost,internetFacing,patched\nA,server,1,maybe,true\n"));
        assertTrue(bad.getMessage().contains("maybe"), bad.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> load(dir, "name,type,isolationCost,internetFacing,patched\nA,server,1,true,true,extra\n"));
        assertThrows(IllegalArgumentException.class,
                () -> load(dir, "name,type,isolationCost\nA,server\n"));
    }

    // ---- the risk score ----------------------------------------------------------------------

    private static EventTimeline quietTimeline() {
        return new EventTimeline(List.of(new SecurityEvent(3, "other", "X", 1, "", "")), 24);
    }

    @Test
    void exposureAddsExplainablePoints() {
        RiskScorer scorer = new RiskScorer();
        EventTimeline t = quietTimeline();

        RiskAssessment exposed = scorer.score("h", 0, 23, t, 0, 0, false, true, false);
        assertEquals(15, exposed.score());
        assertTrue(exposed.reasons().contains("internet-facing and unpatched (+15)"));

        RiskAssessment internal = scorer.score("h", 0, 23, t, 0, 0, false, false, false);
        assertEquals(5, internal.score());
        assertTrue(internal.reasons().contains("unpatched (+5)"));

        RiskAssessment patched = scorer.score("h", 0, 23, t, 0, 0, false, true, true);
        assertEquals(0, patched.score(), "internet-facing but patched adds nothing");
        assertTrue(patched.reasons().isEmpty());
    }

    @Test
    void oldScoringCallBehavesAsBefore() {
        RiskScorer scorer = new RiskScorer();
        EventTimeline t = quietTimeline();
        assertEquals(scorer.score("h", 0, 23, t, 1, 1, true).score(),
                scorer.score("h", 0, 23, t, 1, 1, true, false, true).score());
    }

    @Test
    void scoreIsStillCappedAtOneHundred() {
        EventTimeline busy = new EventTimeline(List.of(new SecurityEvent(3, "h", "X", 50, "", "")), 24);
        RiskAssessment loud = new RiskScorer().score("h", 0, 23, busy, 5, 5, true, true, false);
        assertEquals(100, loud.score(), "30 + 10 + 30 + 20 + 10 + 15 = 115, capped");
    }

    // ---- the sample data ---------------------------------------------------------------------

    @Test
    void sampleDataMarksWebServerExposedAndUnpatched() throws IOException {
        DashboardModel model = DashboardModel.load(Path.of("data"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        Topology topo = model.topology();
        assertTrue(topo.asset(topo.indexOf("WEB-01")).exposedAndUnpatched());
        assertTrue(topo.asset(topo.indexOf("VPN-GW")).internetFacing());
        assertTrue(topo.asset(topo.indexOf("VPN-GW")).patched());

        Incident web = model.incidentFor("WEB-01");
        assertEquals(81, web.riskScore());
        assertTrue(web.reasons().contains("internet-facing and unpatched (+15)"));
        Incident app = model.incidentFor("APP-01");
        assertEquals(62, app.riskScore());
        assertTrue(app.reasons().contains("unpatched (+5)"));
        assertEquals(30, model.incidentFor("VPN-GW").riskScore(), "patched hosts get no exposure points");
    }

    // ---- the what-if ranking -----------------------------------------------------------------

    @Test
    void anExposedUnpatchedHostRanksAheadEvenWhenCheaperToContain() {
        Topology topo = new Topology(
                List.of(new Asset("X", "server", 9, false, true),
                        new Asset("Z", "server", 9, true, false),
                        new Asset("T", "database", 100)),
                List.of(new Link(0, 2, 50, false), new Link(1, 2, 3, false)));
        DashboardModel model = new DashboardModel(topo, List.of(), IocEngine.fromLines(List.of()), List.of());
        model.analyse("X", "T", 0, 23);
        List<DashboardModel.WhatIfRow> rows = model.whatIf();
        assertEquals("Z", rows.get(0).host());
        assertEquals(3, rows.get(0).costA());
        assertEquals("X", rows.get(1).host());
        assertEquals(50, rows.get(1).costA());
        assertTrue(rows.get(0).internetFacing());
        assertFalse(rows.get(0).patched());
    }
}