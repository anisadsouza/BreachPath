package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.ui.DashboardModel;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Headless tests for the Investigation tab data: wildcard pattern hits and indicator prefix search. */
class DashboardInvestigationTest {
    private DashboardModel model;

    @BeforeEach
    void load() throws IOException {
        model = DashboardModel.load(Path.of("data"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
    }

    @Test
    void wildcardPatternsReportTheCommandsTheyMatch() {
        Map<String, List<String>> hits = model.patternMatches();
        assertEquals(List.of("powershell"), hits.get("p.wershell"));
        assertEquals(List.of("mimikatz"), hits.get("mimikat."));
        assertTrue(hits.values().stream().noneMatch(List::isEmpty), "every sample pattern should match something");
    }

    @Test
    void patternMatchesNeedAnalysisFirst() throws IOException {
        DashboardModel fresh = DashboardModel.load(Path.of("data"));
        assertThrows(IllegalStateException.class, fresh::patternMatches);
    }

    @Test
    void iocSearchFindsByPrefix() {
        assertEquals(List.of("update-cdn.evil-domain.com"), model.searchIoc("update"));
        assertTrue(model.searchIoc("203.0").contains("203.0.113.*"));
    }

    @Test
    void iocSearchIsForgivingAboutInput() {
        assertEquals(model.searchIoc("update"), model.searchIoc("  update  "));
        assertTrue(model.searchIoc("no-such-indicator").isEmpty());
        assertFalse(model.searchIoc(null).isEmpty());
        assertFalse(model.searchIoc("").isEmpty());
    }
}