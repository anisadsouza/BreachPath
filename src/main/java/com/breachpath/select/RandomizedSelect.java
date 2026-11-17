package com.breachpath.select;

import java.util.Random;

/**
 * Randomized Quickselect: finds the k-th smallest value of an unsorted array without sorting it.
 *
 * <p>Each round picks a uniformly random pivot, partitions the range into values less than, equal
 * to and greater than the pivot (three-way, so many equal values do not degrade it), and keeps
 * only the side that contains the target rank. The expected number of comparisons is O(n)
 * (about 3.4 n for the median) for every input, because the random pivot makes the worst case
 * O(n^2) depend on bad luck, not on the data. A full sort needs O(n log n).
 *
 * <p>The input array is never modified. Pass a seeded {@link Random} for repeatable runs.
 */
public final class RandomizedSelect {
    private RandomizedSelect() {
    }

    /** The selected value and how many element comparisons were made to find it. */
    public record Result(int value, long comparisons) {
    }

    /**
     * @param k zero-based rank: 0 is the minimum, data.length - 1 the maximum
     * @throws IllegalArgumentException for null or empty data, or k outside [0, length)
     */
    public static Result kthSmallest(int[] data, int k, Random rnd) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Cannot select from an empty array");
        }
        if (k < 0 || k >= data.length) {
            throw new IllegalArgumentException("Rank " + k + " is outside [0, " + (data.length - 1) + "]");
        }
        if (rnd == null) {
            throw new IllegalArgumentException("A random source is required");
        }
        int[] a = data.clone();
        int lo = 0;
        int hi = a.length - 1;
        long comparisons = 0;
        while (lo < hi) {
            int pivot = a[lo + rnd.nextInt(hi - lo + 1)];
            // Dutch national flag partition: a[lo..lt-1] < pivot, a[lt..gt] == pivot, a[gt+1..hi] > pivot.
            int lt = lo;
            int gt = hi;
            int i = lo;
            while (i <= gt) {
                comparisons++;
                if (a[i] < pivot) {
                    swap(a, lt++, i++);
                } else if (a[i] > pivot) {
                    swap(a, i, gt--);
                } else {
                    i++;
                }
            }
            if (k < lt) {
                hi = lt - 1;
            } else if (k > gt) {
                lo = gt + 1;
            } else {
                return new Result(pivot, comparisons);
            }
        }
        return new Result(a[lo], comparisons);
    }

    /** The k-th largest value (zero-based: 0 is the maximum). */
    public static Result kthLargest(int[] data, int k, Random rnd) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Cannot select from an empty array");
        }
        if (k < 0 || k >= data.length) {
            throw new IllegalArgumentException("Rank " + k + " is outside [0, " + (data.length - 1) + "]");
        }
        return kthSmallest(data, data.length - 1 - k, rnd);
    }

    /**
     * Nearest-rank percentile: the smallest value that is at least p percent of the data.
     *
     * @param percent in (0, 100]; 100 gives the maximum
     */
    public static Result percentile(int[] data, double percent, Random rnd) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Cannot take a percentile of an empty array");
        }
        if (!(percent > 0.0 && percent <= 100.0)) {
            throw new IllegalArgumentException("Percentile must be in (0, 100]: " + percent);
        }
        int rank = (int) Math.ceil(percent / 100.0 * data.length) - 1;
        return kthSmallest(data, Math.max(0, Math.min(data.length - 1, rank)), rnd);
    }

    /** Median as the lower middle element (rank (n - 1) / 2), so it is always a value from the data. */
    public static Result median(int[] data, Random rnd) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Cannot take the median of an empty array");
        }
        return kthSmallest(data, (data.length - 1) / 2, rnd);
    }

    private static void swap(int[] a, int i, int j) {
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
    }
}