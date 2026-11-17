package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.bloom.BloomFilter;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Bloom filter: no false negatives, a measured false-positive rate near the target, and bad input rejected. */
class BloomFilterTest {

    private static String word(Random rnd) {
        StringBuilder sb = new StringBuilder();
        int len = 8 + rnd.nextInt(20);
        for (int i = 0; i < len; i++) {
            sb.append((char) ('a' + rnd.nextInt(26)));
        }
        return sb.toString();
    }

    @Test
    void neverHasAFalseNegative() {
        Random rnd = new Random(1);
        BloomFilter f = new BloomFilter(10_000, 0.01);
        Set<String> added = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            String w = word(rnd);
            added.add(w);
            f.add(w);
        }
        for (String w : added) {
            assertTrue(f.mightContain(w), "missing " + w);
        }
    }

    @Test
    void emptyFilterRejectsEverything() {
        BloomFilter f = new BloomFilter(100, 0.01);
        Random rnd = new Random(2);
        for (int i = 0; i < 1_000; i++) {
            assertFalse(f.mightContain(word(rnd)));
        }
        assertEquals(0, f.setBits());
        assertEquals(0.0, f.estimatedFalsePositiveRate(), 0.0);
    }

    @Test
    void measuredFalsePositiveRateIsNearTheTarget() {
        Random rnd = new Random(3);
        int n = 20_000;
        BloomFilter f = new BloomFilter(n, 0.01);
        Set<String> members = new HashSet<>();
        while (members.size() < n) {
            members.add(word(rnd));
        }
        for (String m : members) {
            f.add(m);
        }
        int probes = 100_000;
        int falsePositives = 0;
        int tested = 0;
        while (tested < probes) {
            String w = word(rnd);
            if (members.contains(w)) {
                continue;
            }
            tested++;
            if (f.mightContain(w)) {
                falsePositives++;
            }
        }
        double rate = (double) falsePositives / probes;
        assertTrue(rate < 0.02, "false positive rate " + rate + " is more than twice the 1% target");
        assertEquals(0.01, f.estimatedFalsePositiveRate(), 0.005);
        assertEquals(0.5, f.fillRatio(), 0.05);
    }

    @Test
    void sizingFollowsTheStandardFormulas() {
        // m = -n ln p / (ln 2)^2 = 9586 bits and k = 7 for n = 1000, p = 0.01.
        assertEquals(9586, BloomFilter.optimalBits(1000, 0.01), 1);
        assertEquals(7, BloomFilter.optimalHashes(1000, BloomFilter.optimalBits(1000, 0.01)));
        BloomFilter f = new BloomFilter(1000, 0.01);
        assertEquals(7, f.hashCount());
        assertEquals(9586, f.bitSize(), 1);
        assertTrue(new BloomFilter(1000, 0.001).bitSize() > f.bitSize(), "a lower rate needs more bits");
    }

    @Test
    void invalidParametersAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(-1, 0.01));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, 0.0));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, 1.0));
        assertThrows(IllegalArgumentException.class, () -> new BloomFilter(10, Double.NaN));
        BloomFilter f = new BloomFilter(10, 0.01);
        assertThrows(IllegalArgumentException.class, () -> f.add(null));
        assertThrows(IllegalArgumentException.class, () -> f.mightContain(null));
    }

    @Test
    void addingTheSameItemTwiceChangesNothing() {
        BloomFilter f = new BloomFilter(100, 0.01);
        assertTrue(f.add("185.220.101.7"));
        long bits = f.setBits();
        assertFalse(f.add("185.220.101.7"));
        assertEquals(bits, f.setBits());
        assertEquals(2, f.additions());
    }

    @Test
    void boundaryItemsWork() {
        BloomFilter zero = new BloomFilter(0, 0.01); // zero expected items is treated as one
        assertTrue(zero.bitSize() >= 64);
        zero.add("");
        assertTrue(zero.mightContain(""));
        zero.add("café-中文");
        assertTrue(zero.mightContain("café-中文"));
        assertFalse(new BloomFilter(10, 0.01).mightContain("not-added"));
    }

    @Test
    void sameInputGivesTheSameBits() {
        BloomFilter a = new BloomFilter(500, 0.01);
        BloomFilter b = new BloomFilter(500, 0.01);
        for (int i = 0; i < 500; i++) {
            a.add("item-" + i);
            b.add("item-" + i);
        }
        assertEquals(a.setBits(), b.setBits());
        assertEquals(a.estimatedDistinctItems(), b.estimatedDistinctItems(), 0.0);
        assertEquals(500.0, a.estimatedDistinctItems(), 25.0);
    }

    @Test
    void overloadingRaisesTheEstimatedRateAboveTheTarget() {
        BloomFilter f = new BloomFilter(100, 0.01);
        for (int i = 0; i < 5_000; i++) {
            f.add("overload-" + i);
        }
        assertTrue(f.estimatedFalsePositiveRate() > 0.5, "an overfull filter must report a high rate");
    }
}