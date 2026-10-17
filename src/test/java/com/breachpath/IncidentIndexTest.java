package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.IncidentIndex;
import com.breachpath.model.Incident;
import java.util.List;
import org.junit.jupiter.api.Test;

class IncidentIndexTest {

    @Test
    void topReturnsHighestRiskFirst() {
        IncidentIndex idx = new IncidentIndex();
        idx.open("low", 10, List.of());
        idx.open("high", 90, List.of());
        idx.open("mid", 50, List.of());
        List<Incident> top = idx.top(2);
        assertEquals("high", top.get(0).host());
        assertEquals("mid", top.get(1).host());
    }

    @Test
    void equalScoresAreOrderedByOlderIncidentFirst() {
        IncidentIndex idx = new IncidentIndex();
        Incident first = idx.open("first", 70, List.of());
        Incident second = idx.open("second", 70, List.of());
        List<Incident> top = idx.top(2);
        assertEquals(first.id(), top.get(0).id());
        assertEquals(second.id(), top.get(1).id());
        assertEquals(2, idx.size());
    }

    @Test
    void updatingScoreMovesIncidentAndKeepsTreeValid() {
        IncidentIndex idx = new IncidentIndex();
        Incident a = idx.open("a", 20, List.of("start"));
        idx.open("b", 60, List.of());
        assertTrue(idx.updateScore(a.id(), 95, "new evidence"));
        assertEquals("a", idx.top(1).get(0).host());
        assertEquals(List.of("start", "new evidence"), idx.find(a.id()).reasons());
        assertEquals(2, idx.size());
        assertTrue(idx.isBalanced());
        assertFalse(idx.updateScore(999, 1, null));
    }

    @Test
    void closingRemovesIncident() {
        IncidentIndex idx = new IncidentIndex();
        Incident a = idx.open("a", 20, List.of());
        idx.open("b", 60, List.of());
        assertTrue(idx.close(a.id()));
        assertFalse(idx.close(a.id()));
        assertEquals(1, idx.size());
        assertEquals("b", idx.top(5).get(0).host());
    }
}
