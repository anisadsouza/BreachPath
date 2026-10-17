package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.breachpath.segmenttree.SegmentTree;
import java.util.Random;
import org.junit.jupiter.api.Test;

class SegmentTreeTest {

    @Test
    void rangeSumAndMax() {
        SegmentTree t = new SegmentTree(new int[]{1, 3, 5, 7, 9, 11});
        assertEquals(15, t.rangeSum(1, 3));
        assertEquals(7, t.rangeMax(1, 3));
        assertEquals(36, t.rangeSum(0, 5));
        assertEquals(11, t.rangeMax(0, 5));
        assertEquals(5, t.rangeSum(2, 2));
    }

    @Test
    void pointUpdateChangesQueries() {
        SegmentTree t = new SegmentTree(new int[]{1, 3, 5, 7, 9, 11});
        t.update(1, 10);
        assertEquals(16, t.rangeSum(0, 2));
        assertEquals(10, t.rangeMax(0, 2));
        t.update(1, 10);
        assertEquals(16, t.rangeSum(0, 2));
    }

    @Test
    void singleElementTree() {
        SegmentTree t = new SegmentTree(new int[]{42});
        assertEquals(42, t.rangeSum(0, 0));
        assertEquals(42, t.rangeMax(0, 0));
    }

    @Test
    void invalidRangesAreRejected() {
        SegmentTree t = new SegmentTree(new int[]{1, 2, 3});
        assertThrows(IllegalArgumentException.class, () -> t.rangeSum(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> t.rangeSum(2, 3));
        assertThrows(IllegalArgumentException.class, () -> t.rangeMax(2, 1));
        assertThrows(IllegalArgumentException.class, () -> t.update(3, 1));
        assertThrows(IllegalArgumentException.class, () -> new SegmentTree(new int[0]));
    }

    @Test
    void matchesNaiveScanOnRandomData() {
        Random rnd = new Random(11);
        int n = 300;
        int[] data = new int[n];
        for (int i = 0; i < n; i++) {
            data[i] = rnd.nextInt(50);
        }
        SegmentTree t = new SegmentTree(data);
        for (int step = 0; step < 2000; step++) {
            if (rnd.nextBoolean()) {
                int idx = rnd.nextInt(n);
                int val = rnd.nextInt(50);
                data[idx] = val;
                t.update(idx, val);
            } else {
                int a = rnd.nextInt(n);
                int b = rnd.nextInt(n);
                int l = Math.min(a, b);
                int r = Math.max(a, b);
                int sum = 0;
                int max = Integer.MIN_VALUE;
                for (int i = l; i <= r; i++) {
                    sum += data[i];
                    max = Math.max(max, data[i]);
                }
                assertEquals(sum, t.rangeSum(l, r));
                assertEquals(max, t.rangeMax(l, r));
            }
        }
    }
}
