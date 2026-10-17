package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.EventTimeline;
import com.breachpath.engine.IocEngine;
import com.breachpath.engine.PatternEngine;
import com.breachpath.engine.RiskAssessment;
import com.breachpath.engine.RiskScorer;
import com.breachpath.model.SecurityEvent;
import java.util.List;
import org.junit.jupiter.api.Test;

class AnalysisEnginesTest {

    @Test
    void iocEngineHandlesExactAndPrefixRules() {
        IocEngine e = IocEngine.fromLines(List.of("Evil.COM", "/var/tmp/*", "203.0.113.*"));
        assertTrue(e.isKnownIndicator("evil.com"));
        assertFalse(e.isKnownIndicator("evil.com.au"));
        assertTrue(e.isKnownIndicator("/var/tmp/dump.bin"));
        assertTrue(e.isKnownIndicator("203.0.113.50"));
        assertFalse(e.isKnownIndicator("203.0.114.1"));
        assertFalse(e.isKnownIndicator(""));
        assertEquals(List.of("203.0.113.*"), e.search("203"));
    }

    @Test
    void patternEngineMatchesWildcards() {
        PatternEngine p = new PatternEngine(List.of("PowerShell", "psexec", "ipconfig"));
        assertEquals(List.of("powershell"), p.match("p.wershell"));
        assertEquals(List.of("psexec"), p.match("ps.xec"));
        assertEquals(List.of(), p.match("nothing"));
    }

    @Test
    void timelineAnswersWindowQueriesAndUpdates() {
        List<SecurityEvent> events = List.of(
                new SecurityEvent(1, "h1", "FAILED_LOGIN", 4, "", ""),
                new SecurityEvent(1, "h1", "FAILED_LOGIN", 6, "", ""),
                new SecurityEvent(5, "h1", "FAILED_LOGIN", 3, "", ""));
        EventTimeline t = new EventTimeline(events, 24);
        assertEquals(13, t.total("h1", 0, 23));
        assertEquals(10, t.peak("h1", 0, 23));
        assertEquals(3, t.peak("h1", 2, 23));
        assertEquals(0, t.total("unknown", 0, 23));
        t.addAlerts("h1", 5, 20);
        assertEquals(23, t.peak("h1", 0, 23));
        assertThrows(IllegalArgumentException.class, () -> t.total("h1", 5, 2));
        assertThrows(IllegalArgumentException.class, () -> t.total("h1", 0, 24));
    }

    @Test
    void riskScoreIsCappedAndExplained() {
        EventTimeline t = new EventTimeline(
                List.of(new SecurityEvent(2, "h", "X", 50, "", "")), 24);
        RiskAssessment quiet = new RiskScorer().score("nobody", 0, 23, t, 0, 0, false);
        assertEquals(0, quiet.score());
        assertTrue(quiet.reasons().isEmpty());
        RiskAssessment loud = new RiskScorer().score("h", 0, 23, t, 5, 5, true);
        assertEquals(100, loud.score());
        assertFalse(loud.reasons().isEmpty());
    }
}
