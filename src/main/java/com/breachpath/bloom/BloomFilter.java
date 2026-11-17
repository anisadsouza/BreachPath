package com.breachpath.bloom;

/**
 * Bloom filter: a probabilistic set with no false negatives and a tunable false-positive rate.
 *
 * <p>Sizing: for n expected insertions and target false-positive rate p, the bit array has
 * m = -n ln p / (ln 2)^2 bits and k = (m / n) ln 2 hash functions. The k indexes of an item come
 * from two independent 64-bit hashes combined as h1 + i * h2 (Kirsch-Mitzenmacher double hashing).
 *
 * <p>Meaning of the answers: {@link #mightContain} returning false is certain (the item was never
 * added). Returning true only means "possibly present": callers that need an exact answer must
 * confirm with an authoritative lookup.
 *
 * <p>Complexity: add and mightContain are O(k + |item|) time; space is m bits, independent of the
 * length of the stored items. Not thread-safe for concurrent writers.
 */
public final class BloomFilter {
    private static final long FNV_PRIME = 0x100000001b3L;
    private static final long FNV_BASIS_1 = 0xcbf29ce484222325L;
    private static final long FNV_BASIS_2 = 0x84222325cbf29ce4L;

    private final long[] words;
    private final long bits;
    private final int hashes;
    private final int expectedInsertions;
    private final double targetRate;
    private long additions;

    /**
     * @param expectedInsertions how many distinct items will be added (0 is treated as 1)
     * @param falsePositiveRate  target rate at that load, strictly between 0 and 1
     * @throws IllegalArgumentException for a negative count or a rate outside (0, 1)
     */
    public BloomFilter(int expectedInsertions, double falsePositiveRate) {
        if (expectedInsertions < 0) {
            throw new IllegalArgumentException("expectedInsertions must not be negative: " + expectedInsertions);
        }
        if (!(falsePositiveRate > 0.0 && falsePositiveRate < 1.0)) {
            throw new IllegalArgumentException("falsePositiveRate must be between 0 and 1 (exclusive): "
                    + falsePositiveRate);
        }
        int n = Math.max(1, expectedInsertions);
        long m = optimalBits(n, falsePositiveRate);
        this.bits = m;
        this.hashes = optimalHashes(n, m);
        this.words = new long[(int) ((m + 63) / 64)];
        this.expectedInsertions = n;
        this.targetRate = falsePositiveRate;
    }

    /** Bits needed: -n ln p / (ln 2)^2, at least 64. */
    public static long optimalBits(int n, double p) {
        double m = -n * Math.log(p) / (Math.log(2) * Math.log(2));
        long bits = (long) Math.ceil(m);
        if (bits > (long) Integer.MAX_VALUE * 64L) {
            throw new IllegalArgumentException("Filter would need too many bits for n=" + n + ", p=" + p);
        }
        return Math.max(64, bits);
    }

    /** Hash count: (m / n) ln 2, at least 1. */
    public static int optimalHashes(int n, long m) {
        return Math.max(1, (int) Math.round((double) m / n * Math.log(2)));
    }

    /** Adds an item. Returns true if at least one new bit was set (so it was certainly new). */
    public boolean add(String item) {
        requireItem(item);
        long h1 = hash(item, FNV_BASIS_1);
        long h2 = hash(item, FNV_BASIS_2) | 1L;
        boolean changed = false;
        for (int i = 0; i < hashes; i++) {
            long idx = Math.floorMod(h1 + i * h2, bits);
            int w = (int) (idx >>> 6);
            long mask = 1L << (idx & 63);
            if ((words[w] & mask) == 0) {
                words[w] |= mask;
                changed = true;
            }
        }
        additions++;
        return changed;
    }

    /** False means definitely absent; true means possibly present. */
    public boolean mightContain(String item) {
        requireItem(item);
        long h1 = hash(item, FNV_BASIS_1);
        long h2 = hash(item, FNV_BASIS_2) | 1L;
        for (int i = 0; i < hashes; i++) {
            long idx = Math.floorMod(h1 + i * h2, bits);
            if ((words[(int) (idx >>> 6)] & (1L << (idx & 63))) == 0) {
                return false;
            }
        }
        return true;
    }

    /** Number of add calls so far (duplicates counted). */
    public long additions() {
        return additions;
    }

    public long bitSize() {
        return bits;
    }

    public int hashCount() {
        return hashes;
    }

    public int expectedInsertions() {
        return expectedInsertions;
    }

    public double targetFalsePositiveRate() {
        return targetRate;
    }

    /** Number of bits currently set to 1. */
    public long setBits() {
        long c = 0;
        for (long w : words) {
            c += Long.bitCount(w);
        }
        return c;
    }

    /** Fraction of bits set; a healthy filter at its design load is close to 0.5. */
    public double fillRatio() {
        return (double) setBits() / bits;
    }

    /**
     * Current false-positive probability estimated from the fill ratio: (set bits / m)^k.
     * This rises above the target if more items than expected were added.
     */
    public double estimatedFalsePositiveRate() {
        return Math.pow(fillRatio(), hashes);
    }

    /** Estimated number of distinct items: -(m / k) ln(1 - X / m), where X is the set-bit count. */
    public double estimatedDistinctItems() {
        double x = setBits();
        if (x >= bits) {
            return Double.POSITIVE_INFINITY;
        }
        return -((double) bits / hashes) * Math.log(1.0 - x / bits);
    }

    /** FNV-1a over the UTF-16 code units, then a splitmix64 finaliser so every input bit affects every output bit. */
    private static long hash(String s, long basis) {
        long h = basis;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= FNV_PRIME;
        }
        h ^= h >>> 30;
        h *= 0xbf58476d1ce4e5b9L;
        h ^= h >>> 27;
        h *= 0x94d049bb133111ebL;
        h ^= h >>> 31;
        return h;
    }

    private static void requireItem(String item) {
        if (item == null) {
            throw new IllegalArgumentException("item must not be null");
        }
    }
}