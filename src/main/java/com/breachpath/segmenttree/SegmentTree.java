package com.breachpath.segmenttree;

/**
 * Segment tree supporting range sum, range maximum and point update.
 * All ranges are inclusive and 0-based.
 */
public class SegmentTree {
    private final int n;
    private final int[] sum;
    private final int[] max;

    public SegmentTree(int[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data must not be empty");
        }
        n = data.length;
        sum = new int[4 * n];
        max = new int[4 * n];
        build(1, 0, n - 1, data);
    }

    public int size() {
        return n;
    }

    public int rangeSum(int left, int right) {
        checkRange(left, right);
        return querySum(1, 0, n - 1, left, right);
    }

    public int rangeMax(int left, int right) {
        checkRange(left, right);
        return queryMax(1, 0, n - 1, left, right);
    }

    /** Sets position {@code index} to {@code value}. */
    public void update(int index, int value) {
        checkRange(index, index);
        update(1, 0, n - 1, index, value);
    }

    public int get(int index) {
        return rangeSum(index, index);
    }

    private void build(int node, int l, int r, int[] data) {
        if (l == r) {
            sum[node] = data[l];
            max[node] = data[l];
            return;
        }
        int mid = (l + r) >>> 1;
        build(2 * node, l, mid, data);
        build(2 * node + 1, mid + 1, r, data);
        pull(node);
    }

    private void pull(int node) {
        sum[node] = sum[2 * node] + sum[2 * node + 1];
        max[node] = Math.max(max[2 * node], max[2 * node + 1]);
    }

    private int querySum(int node, int nl, int nr, int l, int r) {
        if (l <= nl && nr <= r) {
            return sum[node];
        }
        int mid = (nl + nr) >>> 1;
        int s = 0;
        if (l <= mid) {
            s += querySum(2 * node, nl, mid, l, r);
        }
        if (r > mid) {
            s += querySum(2 * node + 1, mid + 1, nr, l, r);
        }
        return s;
    }

    private int queryMax(int node, int nl, int nr, int l, int r) {
        if (l <= nl && nr <= r) {
            return max[node];
        }
        int mid = (nl + nr) >>> 1;
        int best = Integer.MIN_VALUE;
        if (l <= mid) {
            best = Math.max(best, queryMax(2 * node, nl, mid, l, r));
        }
        if (r > mid) {
            best = Math.max(best, queryMax(2 * node + 1, mid + 1, nr, l, r));
        }
        return best;
    }

    private void update(int node, int l, int r, int index, int value) {
        if (l == r) {
            sum[node] = value;
            max[node] = value;
            return;
        }
        int mid = (l + r) >>> 1;
        if (index <= mid) {
            update(2 * node, l, mid, index, value);
        } else {
            update(2 * node + 1, mid + 1, r, index, value);
        }
        pull(node);
    }

    private void checkRange(int l, int r) {
        if (l < 0 || r >= n || l > r) {
            throw new IllegalArgumentException("Invalid range [" + l + ", " + r + "] for size " + n);
        }
    }
}
