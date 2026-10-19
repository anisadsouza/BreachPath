package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.ui.BenchmarkSummary;
import com.breachpath.ui.BenchmarkSummary.Row;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The summary parser is checked against the exact output format of Benchmarks.runAll(). */
class BenchmarkSummaryTest {
    private static final String SAMPLE = String.join("\n",
            "== Flow algorithms vs brute-force minimum cut (small random graphs) ==",
            "200 random graphs checked, mismatches: 0",
            "",
            "== Max flow: Edmonds-Karp vs Ford-Fulkerson (generated graphs) ==",
            "nodes    edges    max flow   EK (ms)        FF (ms)        match ",
            "100      597      545        1.08           29.64          true  ",
            "200      1190     155        1.10           20.32          true  ",
            "400      2396     173        11.51          53.76          true  ",
            "",
            "== Prefix Trie vs linear scan (100,000 words, 500 prefix queries) ==",
            "trie: 16.95 ms   linear scan: 1086.23 ms   results match: true",
            "",
            "== Wildcard dictionary vs naive scan (50,000 words, 200 patterns) ==",
            "dictionary: 8.69 ms   naive scan: 130.23 ms   results match: true",
            "",
            "== Segment tree vs naive scan (200,000 slots, 20,000 queries, 10,000 updates) ==",
            "segment tree: 40.69 ms   naive scan: 1199.63 ms   results match: true",
            "",
            "== Red-black tree vs java.util.TreeMap (100,000 keys, remove 50,000) ==",
            "insert: 70.19 ms   remove: 160.01 ms   height after insert: 20 (log2 n = 16.6)",
            "invariants hold after insert: true, after remove: true, matches TreeMap: true",
            "",
            "Note: these are experiments on synthetic data, not proof of real-world protection.");

    @Test
    void summarisesAllFiveConceptsInOrder() {
        List<Row> rows = BenchmarkSummary.parse(SAMPLE);
        assertEquals(5, rows.size());
        assertEquals(List.of("Max flow / min cut", "Prefix trie", "Wildcard dictionary", "Segment tree",
                "Red-black tree"), rows.stream().map(Row::concept).toList());
        assertTrue(rows.stream().allMatch(Row::passed));
    }

    @Test
    void flowRowUsesTheLargestGraphAndOnlyMentionsEdmondsKarp() {
        Row flow = BenchmarkSummary.parse(SAMPLE).get(0);
        assertTrue(flow.check().contains("200 random graphs"));
        assertEquals("Edmonds-Karp: 400 nodes, 2,396 edges in 11.51 ms", flow.performance());
        assertFalse((flow.check() + flow.performance()).contains("Ford"));
    }

    @Test
    void speedRatiosAreComputed() {
        Row trie = BenchmarkSummary.parse(SAMPLE).get(1);
        assertTrue(trie.performance().contains("64\u00d7 faster"), trie.performance());
        assertEquals("100,000 words, 500 prefix queries", trie.workload());
        Row rb = BenchmarkSummary.parse(SAMPLE).get(4);
        assertTrue(rb.performance().contains("230.2 ms"), rb.performance());
        assertTrue(rb.performance().contains("height 20"));
    }

    @Test
    void failuresAreReportedNotHidden() {
        String bad = SAMPLE.replace("mismatches: 0", "mismatches: 3")
                .replace("linear scan: 1086.23 ms   results match: true", "linear scan: 1086.23 ms   results match: false")
                .replace("matches TreeMap: true", "matches TreeMap: false");
        List<Row> rows = BenchmarkSummary.parse(bad);
        assertFalse(rows.get(0).passed());
        assertTrue(rows.get(0).check().startsWith("3 of 200"));
        assertFalse(rows.get(1).passed());
        assertTrue(rows.get(2).passed());
        assertFalse(rows.get(4).passed());
    }

    @Test
    void garbageOrEmptyInputGivesFiveFailedRowsAndNoException() {
        for (String input : new String[]{"", null, "nonsense\nmore nonsense", "== Prefix Trie vs linear scan ==\nbroken"}) {
            List<Row> rows = BenchmarkSummary.parse(input);
            assertEquals(5, rows.size());
            assertTrue(rows.stream().noneMatch(Row::passed));
        }
    }

    @Test
    void detailViewKeepsEverythingButDropsTheFordFulkersonColumns() {
        String detail = BenchmarkSummary.detailForDisplay(SAMPLE);
        assertFalse(detail.contains("Ford"));
        assertFalse(detail.contains("FF (ms)"));
        assertFalse(detail.contains("29.64"));
        assertTrue(detail.contains("== Max flow: Edmonds-Karp (generated graphs) =="));
        assertTrue(detail.contains("11.51"));
        assertTrue(detail.contains("== Red-black tree vs java.util.TreeMap"));
        assertTrue(detail.contains("Note: these are experiments on synthetic data"));
        assertEquals("", BenchmarkSummary.detailForDisplay(null));
    }
}