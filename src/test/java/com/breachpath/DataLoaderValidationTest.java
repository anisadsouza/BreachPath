package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.model.SecurityEvent;
import com.breachpath.model.Topology;
import com.breachpath.storage.DataLoader;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Bad input must be rejected with a message that says where the problem is, never loaded silently. */
class DataLoaderValidationTest {
    private static final String ASSETS = "name,type,isolationCost,internetFacing,patched\n"
            + "A,workstation,5,false,true\nB,server,20,true,false\n";
    private static final String EDGES = "from,to,cost,bidirectional\nA,B,10,true\n";

    private static String message(Runnable r) {
        try {
            r.run();
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
        throw new AssertionError("expected IllegalArgumentException");
    }

    @Test
    void validTextLoads() {
        Topology t = DataLoader.parseTopology(ASSETS, EDGES);
        assertEquals(2, t.size());
        assertEquals(1, t.links().size());
        assertTrue(t.asset(1).exposedAndUnpatched());
    }

    @Test
    void emptyAssetFileIsRejected() {
        assertTrue(message(() -> DataLoader.parseTopology("", EDGES)).contains("no assets"));
        assertTrue(message(() -> DataLoader.parseTopology("name,type,isolationCost\n# only a comment\n", EDGES))
                .contains("no assets"));
    }

    @Test
    void missingHeaderIsRejectedInsteadOfLosingTheFirstRow() {
        String msg = message(() -> DataLoader.parseTopology("A,workstation,5\nB,server,9\n", EDGES));
        assertTrue(msg.contains("header"), msg);
    }

    @Test
    void duplicateAssetsAreRejected() {
        String dup = ASSETS + "A,workstation,7,false,true\n";
        assertTrue(message(() -> DataLoader.parseTopology(dup, EDGES)).contains("Duplicate asset: A"));
    }

    @Test
    void badNumbersNameTheLineAndColumn() {
        String text = "name,type,isolationCost\nA,workstation,five\n";
        String msg = message(() -> DataLoader.parseTopology(text, EDGES));
        assertTrue(msg.contains("line 2") && msg.contains("isolationCost") && msg.contains("five"), msg);
        String negative = "name,type,isolationCost\nA,workstation,-3\nB,server,4\n";
        assertTrue(message(() -> DataLoader.parseTopology(negative, EDGES)).contains("between 0 and"));
        String huge = "name,type,isolationCost\nA,workstation,2000000\nB,server,4\n";
        assertTrue(message(() -> DataLoader.parseTopology(huge, EDGES)).contains("between 0 and"));
    }

    @Test
    void linksToUnknownAssetsOrWithBadFlagsAreRejected() {
        String unknown = "from,to,cost,bidirectional\nA,GHOST,3,true\n";
        assertTrue(message(() -> DataLoader.parseTopology(ASSETS, unknown)).contains("Unknown asset"));
        String badFlag = "from,to,cost,bidirectional\nA,B,3,maybe\n";
        assertTrue(message(() -> DataLoader.parseTopology(ASSETS, badFlag)).contains("bidirectional"));
        String wrongColumns = "from,to,cost,bidirectional\nA,B,3\n";
        assertTrue(message(() -> DataLoader.parseTopology(ASSETS, wrongColumns)).contains("columns"));
    }

    @Test
    void noLinksAtAllIsAllowed() {
        assertEquals(0, DataLoader.parseTopology(ASSETS, "from,to,cost,bidirectional\n").links().size());
        assertEquals(0, DataLoader.parseTopology(ASSETS, "").links().size());
    }

    @Test
    void eventRowsAreRangeChecked() {
        String head = "hour,host,eventType,count,indicator,command\n";
        assertTrue(message(() -> DataLoader.parseEvents(head + "24,A,LOGIN,1,-,-\n")).contains("hour must be 0 to 23"));
        assertTrue(message(() -> DataLoader.parseEvents(head + "-1,A,LOGIN,1,-,-\n")).contains("hour must be 0 to 23"));
        assertTrue(message(() -> DataLoader.parseEvents(head + "3,A,LOGIN,-5,-,-\n")).contains("must not be negative"));
        assertTrue(message(() -> DataLoader.parseEvents(head + "3,,LOGIN,2,-,-\n")).contains("host is empty"));
        assertTrue(message(() -> DataLoader.parseEvents(head + "x,A,LOGIN,2,-,-\n")).contains("whole number"));
    }

    @Test
    void emptyLogIsAllowedAndDashMeansNone() {
        assertEquals(0, DataLoader.parseEvents("").size());
        assertEquals(0, DataLoader.parseEvents("hour,host,eventType,count,indicator,command\n").size());
        List<SecurityEvent> events = DataLoader.parseEvents(
                "hour,host,eventType,count,indicator,command\n5,A,LOGIN,2,-,powershell\n");
        assertEquals("", events.get(0).indicator());
        assertEquals("powershell", events.get(0).command());
    }

    @Test
    void windowsLineEndingsBomCommentsAndBlankLinesAreHandled() {
        String text = "﻿name,type,isolationCost\r\n# comment\r\n\r\nA,workstation,5\r\nB,server,9\r\n";
        assertEquals(2, DataLoader.parseTopology(text, "from,to,cost,bidirectional\r\n").size());
        assertEquals(List.of("one", "two"), DataLoader.parseLines("# header\n\none\r\n  two  \n"));
        assertFalse(DataLoader.parseLines("").iterator().hasNext());
    }
}