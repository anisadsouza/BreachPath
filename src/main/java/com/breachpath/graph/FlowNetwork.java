package com.breachpath.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Directed flow network stored as a capacity matrix plus the list of original edges. */
public class FlowNetwork {
    private final int n;
    private final int[][] capacity;
    private final List<int[]> edges = new ArrayList<>();

    public FlowNetwork(int n) {
        if (n <= 0) {
            throw new IllegalArgumentException("n must be positive");
        }
        this.n = n;
        this.capacity = new int[n][n];
    }

    /** Adds a directed edge u -> v. Parallel edges add up in the capacity matrix. */
    public void addEdge(int u, int v, int cap) {
        if (u < 0 || v < 0 || u >= n || v >= n || u == v) {
            throw new IllegalArgumentException("Bad edge " + u + " -> " + v);
        }
        if (cap < 0) {
            throw new IllegalArgumentException("Negative capacity");
        }
        capacity[u][v] += cap;
        edges.add(new int[]{u, v, cap});
    }

    public int size() {
        return n;
    }

    /** A fresh copy of the capacity matrix (the residual graph starts as this). */
    public int[][] copyCapacity() {
        int[][] copy = new int[n][];
        for (int i = 0; i < n; i++) {
            copy[i] = capacity[i].clone();
        }
        return copy;
    }

    /** Original edges as {u, v, capacity}. */
    public List<int[]> edges() {
        return Collections.unmodifiableList(edges);
    }
}
