package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.model.Incident;
import com.breachpath.model.IncidentKey;
import com.breachpath.rbtree.RedBlackTree;
import com.breachpath.segmenttree.SegmentTree;
import com.breachpath.ui.DashboardModel;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The read-only views behind the "Under the hood" tab, the Close incident action and the pickers. */
class DashboardInternalsTest {
    private DashboardModel model;

    @BeforeEach
    void load() throws IOException {
        model = DashboardModel.load(Path.of("data"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
    }

    // ---- segment tree ranges ----------------------------------------------------------------

    @Test
    void coveringRangesTileTheQueryExactlyOnce() {
        Random rnd = new Random(4);
        int[] data = new int[37];
        for (int i = 0; i < data.length; i++) {
            data[i] = rnd.nextInt(50);
        }
        SegmentTree tree = new SegmentTree(data);
        for (int l = 0; l < data.length; l += 3) {
            for (int r = l; r < data.length; r += 4) {
                List<int[]> ranges = tree.coveringRanges(l, r);
                int next = l;
                int sum = 0;
                int max = Integer.MIN_VALUE;
                for (int[] range : ranges) {
                    assertEquals(next, range[0], "ranges must be contiguous and in order");
                    next = range[1] + 1;
                    sum += range[2];
                    max = Math.max(max, range[3]);
                }
                assertEquals(r + 1, next);
                assertEquals(tree.rangeSum(l, r), sum);
                assertEquals(tree.rangeMax(l, r), max);
            }
        }
    }

    @Test
    void aWindowQueryUsesFewRangesNotEveryHour() {
        List<int[]> ranges = model.coveringRanges("WS-Alice");
        assertFalse(ranges.isEmpty());
        assertEquals(model.windowTotal("WS-Alice"), ranges.stream().mapToInt(r -> r[2]).sum());
        assertEquals(model.windowPeak("WS-Alice"), ranges.stream().mapToInt(r -> r[3]).max().orElse(-1));
        model.analyse("WS-Alice", "DB-PROD", 3, 14);
        assertTrue(model.coveringRanges("WS-Alice").size() < 12, "fewer ranges than the 12 hours in the window");
        assertTrue(model.coveringRanges("Nobody").isEmpty());
    }

    // ---- red-black tree view ----------------------------------------------------------------

    @Test
    void treeViewIsAValidRedBlackTree() {
        List<RedBlackTree.NodeView<IncidentKey, Incident>> view = model.treeView();
        assertEquals(model.ranked().size(), view.size());
        int roots = 0;
        for (int i = 0; i < view.size(); i++) {
            RedBlackTree.NodeView<IncidentKey, Incident> n = view.get(i);
            if (i > 0) {
                assertTrue(view.get(i - 1).key().compareTo(n.key()) < 0, "in key order");
            }
            if (n.parent() == -1) {
                roots++;
                assertFalse(n.red(), "the root is black");
                assertEquals(0, n.depth());
            } else {
                RedBlackTree.NodeView<IncidentKey, Incident> p = view.get(n.parent());
                assertEquals(p.depth() + 1, n.depth());
                assertFalse(n.red() && p.red(), "no red node has a red parent");
            }
        }
        assertEquals(1, roots);
    }

    @Test
    void treeViewTracksUpdatesAndRemovals() {
        model.addEvidence("DB-PROD", 12, 30);
        assertEquals(11, model.treeView().size());
        assertTrue(model.closeIncident("WS-Alice"));
        List<RedBlackTree.NodeView<IncidentKey, Incident>> view = model.treeView();
        assertEquals(10, view.size());
        assertTrue(view.stream().noneMatch(n -> n.value().host().equals("WS-Alice")));
        assertTrue(model.isBalanced());
    }

    @Test
    void emptyTreeHasEmptyView() {
        for (Incident i : model.ranked()) {
            assertTrue(model.closeIncident(i.host()));
        }
        assertTrue(model.treeView().isEmpty());
        assertTrue(model.ranked().isEmpty());
        assertTrue(model.isBalanced());
    }

    // ---- close incident ---------------------------------------------------------------------

    @Test
    void closingRemovesTheIncidentAndAnalyseBringsItBack() {
        assertTrue(model.closeIncident("WS-Alice"));
        assertNull(model.incidentFor("WS-Alice"));
        assertEquals(10, model.ranked().size());
        assertEquals("AD-01", model.ranked().get(0).host());
        assertFalse(model.closeIncident("WS-Alice"), "already closed");
        assertFalse(model.closeIncident("Nobody"));
        model.analyse("WS-Alice", "DB-PROD", 0, 23);
        assertEquals(11, model.ranked().size());
    }

    @Test
    void newEvidenceReopensAClosedHost() {
        model.closeIncident("DB-PROD");
        assertNull(model.incidentFor("DB-PROD"));
        Incident reopened = model.addEvidence("DB-PROD", 12, 30);
        assertEquals(reopened.id(), model.incidentFor("DB-PROD").id());
        assertTrue(model.isBalanced());
    }

    // ---- trie narrowing and wildcard ---------------------------------------------------------

    @Test
    void indicatorCountsNeverGrowAsYouType() {
        List<Integer> counts = model.iocNarrowing("update");
        assertEquals(6, counts.size());
        for (int i = 1; i < counts.size(); i++) {
            assertTrue(counts.get(i) <= counts.get(i - 1));
        }
        assertEquals(1, counts.get(counts.size() - 1));
        assertTrue(model.iocNarrowing("").isEmpty());
        assertTrue(model.iocNarrowing(null).isEmpty());
        assertEquals(0, model.iocNarrowing("zzz").get(2));
    }

    @Test
    void wildcardPatternsMatchObservedCommands() {
        assertEquals(List.of("powershell"), model.matchPattern("p.wershell"));
        assertEquals(List.of("powershell"), model.matchPattern("  P.WERSHELL "));
        assertTrue(model.matchPattern("zz.zz").isEmpty());
        assertTrue(model.matchPattern("").isEmpty());
        assertTrue(model.matchPattern(null).isEmpty());
    }
}