package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.ContainmentPlanner;
import com.breachpath.engine.IocEngine;
import com.breachpath.model.Asset;
import com.breachpath.model.Incident;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import com.breachpath.ui.DashboardModel;
import com.breachpath.ui.ReportWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The exported HTML report. */
class ReportWriterTest {
    private DashboardModel model;

    @BeforeEach
    void load() throws IOException {
        model = DashboardModel.load(Path.of("data"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
    }

    private static int count(String text, String part) {
        int n = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) {
            n++;
        }
        return n;
    }

    @Test
    void reportHasTheAnalysisIncidentsContainmentAndWhatIf() {
        String html = ReportWriter.html(model, "1 January 2027, 09:30");
        assertTrue(html.startsWith("<!DOCTYPE html>"));
        assertTrue(html.contains("1 January 2027, 09:30"));
        assertTrue(html.contains("<th>Compromised hosts</th><td>WS-Alice</td>"));
        assertTrue(html.contains("<th>Protected targets</th><td>DB-PROD</td>"));
        assertTrue(html.contains("hours 0 to 23"));
        assertTrue(html.contains("Total cost: 18"));
        assertTrue(html.contains("Total cost: 5"));
        assertTrue(html.contains("Block link WS-Alice -&gt; WEB-01"), "action text is escaped");
        assertTrue(html.contains("Verified: no protected target can be reached after the cut."));
        assertTrue(html.contains("internet-facing, unpatched"));
        assertTrue(html.contains("synthetic data"));
    }

    @Test
    void incidentsAreRankedHighestRiskFirst() {
        String html = ReportWriter.html(model, "x");
        int alice = html.indexOf("WS-Alice</td><td>100</td>");
        int ad = html.indexOf("AD-01</td><td>87</td>");
        int db = html.indexOf("DB-PROD</td><td>6</td>");
        assertTrue(alice > 0 && ad > alice && db > ad);
        assertTrue(html.contains("<td>Critical</td>"));
        assertTrue(html.contains("internet-facing and unpatched (+15)"));
    }

    @Test
    void linkCostChangesAppearOnlyWhenThereAreSome() {
        assertFalse(ReportWriter.html(model, "x").contains("Link costs changed from the data file"));
        model.setLinkCost(0, 100);
        String html = ReportWriter.html(model, "x");
        assertTrue(html.contains("Link costs changed from the data file"));
        assertTrue(html.contains("WS-Alice to WEB-01: 10 to 100"));
        assertTrue(html.contains("Total cost: 23"));
    }

    @Test
    void namesAreEscapedSoTheyCannotInjectMarkup() {
        Topology topo = new Topology(
                List.of(new Asset("<b>x&y", "server", 4), new Asset("T", "database", 100)),
                List.of(new Link(0, 1, 5, false)));
        DashboardModel small = new DashboardModel(topo, List.of(), IocEngine.fromLines(List.of()), List.of());
        small.analyse("<b>x&y", "T", 0, 23);
        String html = ReportWriter.html(small, "<script>alert(1)</script>");
        assertFalse(html.contains("<b>x"));
        assertFalse(html.contains("<script>"));
        assertTrue(html.contains("&lt;b&gt;x&amp;y"));
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    @Test
    void anImpossibleCutAndAnUnneededCutAreExplained() {
        Topology stuck = new Topology(
                List.of(new Asset("X", "server", 9), new Asset("T", "database", 100)),
                List.of(new Link(0, 1, ContainmentPlanner.INF, false)));
        DashboardModel a = new DashboardModel(stuck, List.of(), IocEngine.fromLines(List.of()), List.of());
        a.analyse("X", "T", 0, 23);
        String stuckHtml = ReportWriter.html(a, "x");
        assertTrue(stuckHtml.contains("No finite-cost containment exists"));
        assertTrue(stuckHtml.contains("Total cost: 9"), "scenario B can still isolate X");

        Topology apart = new Topology(
                List.of(new Asset("Y", "server", 3), new Asset("T", "database", 100)), List.of());
        DashboardModel b = new DashboardModel(apart, List.of(), IocEngine.fromLines(List.of()), List.of());
        b.analyse("Y", "T", 0, 23);
        assertTrue(ReportWriter.html(b, "x").contains("No action is needed"));
    }

    @Test
    void anEmptyIncidentQueueIsReported() {
        for (Incident i : model.ranked()) {
            model.closeIncident(i.host());
        }
        assertTrue(ReportWriter.html(model, "x").contains("No open incidents."));
    }

    @Test
    void theHtmlIsWellFormedEnoughToOpen() {
        String html = ReportWriter.html(model, "x");
        assertEquals(count(html, "<table>"), count(html, "</table>"));
        assertEquals(count(html, "<tr>"), count(html, "</tr>"));
        assertEquals(1, count(html, "</html>"));
    }

    @Test
    void writeSavesTheSameTextAsUtf8(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("report.html");
        ReportWriter.write(file, model, "today");
        assertEquals(ReportWriter.html(model, "today"), Files.readString(file, StandardCharsets.UTF_8));
    }
}