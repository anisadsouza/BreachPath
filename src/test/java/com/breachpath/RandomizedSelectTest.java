package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.select.RandomizedSelect;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Randomized Quickselect against the sorted array, on random, repeated, sorted and tiny inputs. */
class RandomizedSelectTest {

    @Test
    void matchesTheSortedArrayForEveryRankOnRandomData() {
        Random rnd = new Random(5);
        for (int trial = 0; trial < 300; trial++) {
            int n = 1 + rnd.nextInt(60);
            int[] data = new int[n];
            for (int i = 0; i < n; i++) {
                data[i] = rnd.nextInt(40) - 10; // many repeats and negatives
            }
            int[] sorted = data.clone();
            Arrays.sort(sorted);
            int k = rnd.nextInt(n);
            assertEquals(sorted[k], RandomizedSelect.kthSmallest(data, k, new Random(trial)).value());
        }
    }

    @Test
    void singleElementAndAllEqualValues() {
        assertEquals(7, RandomizedSelect.kthSmallest(new int[]{7}, 0, new Random(1)).value());
        int[] same = new int[1_000];
        Arrays.fill(same, 4);
        RandomizedSelect.Result r = RandomizedSelect.kthSmallest(same, 500, new Random(1));
        assertEquals(4, r.value());
        assertTrue(r.comparisons() <= same.length, "three-way partition must finish an all-equal array in one pass");
    }

    @Test
    void sortedAndReverseSortedInputsAreNotAWorstCase() {
        int n = 20_000;
        int[] up = new int[n];
        int[] down = new int[n];
        for (int i = 0; i < n; i++) {
            up[i] = i;
            down[i] = n - i;
        }
        RandomizedSelect.Result a = RandomizedSelect.kthSmallest(up, n / 2, new Random(9));
        RandomizedSelect.Result b = RandomizedSelect.kthSmallest(down, n / 2, new Random(9));
        assertEquals(n / 2, a.value());
        assertEquals(n / 2 + 1, b.value());
        assertTrue(a.comparisons() < 10L * n, "comparisons " + a.comparisons());
        assertTrue(b.comparisons() < 10L * n, "comparisons " + b.comparisons());
    }

    @Test
    void doesNotModifyTheInput() {
        int[] data = {9, 3, 7, 1, 5};
        int[] copy = data.clone();
        RandomizedSelect.kthSmallest(data, 2, new Random(3));
        assertArrayEquals(copy, data);
    }

    @Test
    void invalidArgumentsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.kthSmallest(new int[0], 0, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.kthSmallest(null, 0, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.kthSmallest(new int[]{1, 2}, -1, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.kthSmallest(new int[]{1, 2}, 2, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.kthSmallest(new int[]{1, 2}, 0, null));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.percentile(new int[]{1}, 0, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.percentile(new int[]{1}, 101, new Random(1)));
        assertThrows(IllegalArgumentException.class, () -> RandomizedSelect.median(new int[0], new Random(1)));
    }

    @Test
    void percentileUsesTheNearestRankRule() {
        int[] scores = {15, 20, 35, 40, 50};
        assertEquals(20, RandomizedSelect.percentile(scores, 30, new Random(1)).value());
        assertEquals(20, RandomizedSelect.percentile(scores, 40, new Random(1)).value());
        assertEquals(35, RandomizedSelect.percentile(scores, 50, new Random(1)).value());
        assertEquals(40, RandomizedSelect.percentile(scores, 75, new Random(1)).value());
        assertEquals(50, RandomizedSelect.percentile(scores, 100, new Random(1)).value());
        assertEquals(15, RandomizedSelect.percentile(scores, 1, new Random(1)).value());
    }

    @Test
    void medianIsTheLowerMiddleValueAndKthLargestMirrorsKthSmallest() {
        assertEquals(2, RandomizedSelect.median(new int[]{4, 1, 3, 2}, new Random(1)).value());
        assertEquals(3, RandomizedSelect.median(new int[]{5, 1, 3}, new Random(1)).value());
        int[] data = {8, 2, 9, 4, 6};
        assertEquals(9, RandomizedSelect.kthLargest(data, 0, new Random(1)).value());
        assertEquals(2, RandomizedSelect.kthLargest(data, 4, new Random(1)).value());
    }

    @Test
    void sameSeedGivesTheSameCostAndComparisonsGrowLinearly() {
        Random gen = new Random(77);
        int[] small = new int[10_000];
        int[] large = new int[100_000];
        for (int i = 0; i < small.length; i++) {
            small[i] = gen.nextInt();
        }
        for (int i = 0; i < large.length; i++) {
            large[i] = gen.nextInt();
        }
        RandomizedSelect.Result first = RandomizedSelect.kthSmallest(large, 90_000, new Random(5));
        RandomizedSelect.Result again = RandomizedSelect.kthSmallest(large, 90_000, new Random(5));
        assertEquals(first.comparisons(), again.comparisons());
        double perSmall = (double) RandomizedSelect.kthSmallest(small, 9_000, new Random(5)).comparisons() / small.length;
        double perLarge = (double) first.comparisons() / large.length;
        assertTrue(perSmall < 8 && perLarge < 8, "per element: " + perSmall + " and " + perLarge);
    }
}