package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.Benchmarks;
import org.junit.jupiter.api.Test;

/** The median that every reported benchmark time is built on. */
class BenchmarkMedianTest {

    @Test
    void oddCountGivesTheMiddleValue() {
        assertEquals(3.0, Benchmarks.median(new double[]{5, 1, 3}), 1e-12);
        assertEquals(7.0, Benchmarks.median(new double[]{7}), 1e-12);
    }

    @Test
    void evenCountAveragesTheTwoMiddleValues() {
        assertEquals(2.5, Benchmarks.median(new double[]{4, 1, 2, 3}), 1e-12);
        assertEquals(10.0, Benchmarks.median(new double[]{10, 10}), 1e-12);
    }

    @Test
    void oneSlowRunDoesNotMoveTheMedian() {
        assertEquals(10.1, Benchmarks.median(new double[]{10.1, 9.9, 10.0, 500.0, 10.2}), 1e-12);
        assertEquals(10.0, Benchmarks.median(new double[]{10.1, 9.9, 10.0, 0.01, 10.2}), 1e-12);
    }

    @Test
    void handlesDuplicatesAndNegativeValues() {
        assertEquals(2.0, Benchmarks.median(new double[]{2, 2, 2, 9, 0}), 1e-12);
        assertEquals(-1.0, Benchmarks.median(new double[]{-3, -1, 4}), 1e-12);
    }

    @Test
    void doesNotChangeTheInputOrder() {
        double[] values = {5, 1, 3};
        Benchmarks.median(values);
        assertArrayEquals(new double[]{5, 1, 3}, values, 0.0);
    }

    @Test
    void emptyInputIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> Benchmarks.median(new double[0]));
    }

    @Test
    void usesAnOddNumberOfTimedRuns() {
        assertTrue(Benchmarks.RUNS >= 3 && Benchmarks.RUNS % 2 == 1);
    }
}