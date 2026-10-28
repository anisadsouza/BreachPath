package com.breachpath.engine;

import com.breachpath.graph.BruteForceMinCut;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.FlowNetwork;
import com.breachpath.graph.MaxFlowResult;
import com.breachpath.rbtree.RedBlackTree;
import com.breachpath.segmenttree.SegmentTree;
import com.breachpath.trie.Trie;
import com.breachpath.trie.WordDictionary;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.TreeMap;

/**
 * Correctness checks and timing experiments on synthetic data (fixed seeds, so repeatable).
 * Every time is the median of {@link #RUNS} runs after one warm-up run, so one slow run does not
 * distort the result.
 */
public final class Benchmarks {
    /** Timed runs behind each reported time. */
    public static final int RUNS = 5;

    private Benchmarks() {
    }

    /** Median of the values: the middle one, or the average of the two middle ones. */
    public static double median(double[] values) {
        if (values.length == 0) {
            throw new IllegalArgumentException("no values");
        }
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        int n = sorted.length;
        return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    }

    /** Runs the task once to warm up the JVM, then {@link #RUNS} timed times; returns the median in ms. */
    private static double medianMs(Runnable task) {
        task.run();
        double[] times = new double[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long start = System.nanoTime();
            task.run();
            times[i] = ms(System.nanoTime() - start);
        }
        return median(times);
    }

    public static void runAll() {
        System.out.println("Each time is the median of " + RUNS + " runs after one warm-up run.");
        System.out.println();
        validateFlows();
        benchFlows();
        benchTrie();
        benchWildcard();
        benchSegmentTree();
        benchRedBlackTree();
        System.out.println();
        System.out.println("Note: these are experiments on synthetic data, not proof of real-world protection.");
    }

    private static double ms(long nanos) {
        return nanos / 1_000_000.0;
    }

    private static FlowNetwork randomNetwork(Random rnd, int n, int m, int maxCap) {
        FlowNetwork net = new FlowNetwork(n);
        for (int i = 0; i < m; i++) {
            int u = rnd.nextInt(n);
            int v = rnd.nextInt(n);
            if (u != v) {
                net.addEdge(u, v, 1 + rnd.nextInt(maxCap));
            }
        }
        return net;
    }

    // ------------------------------------------------------------------ flow

    private static void validateFlows() {
        System.out.println("== Edmonds-Karp vs brute-force minimum cut (small random graphs) ==");
        Random rnd = new Random(1);
        EdmondsKarp ek = new EdmondsKarp();
        int trials = 200;
        int mismatches = 0;
        for (int i = 0; i < trials; i++) {
            int n = 6 + rnd.nextInt(2);
            FlowNetwork net = randomNetwork(rnd, n, 6 + rnd.nextInt(8), 9);
            int brute = BruteForceMinCut.minCutCost(net, 0, n - 1, Integer.MAX_VALUE);
            MaxFlowResult a = ek.compute(net, 0, n - 1);
            if (a.maxFlow() != brute || a.cutCost() != brute) {
                mismatches++;
            }
        }
        System.out.printf("%d random graphs checked, mismatches: %d%n%n", trials, mismatches);
    }

    private static void benchFlows() {
        System.out.println("== Max flow: Edmonds-Karp (generated graphs) ==");
        System.out.printf("%-8s %-8s %-10s %s%n", "nodes", "edges", "max flow", "EK (ms)");
        Random rnd = new Random(2);
        for (int n : new int[]{100, 200, 400}) {
            FlowNetwork net = randomNetwork(rnd, n, n * 5, 100);
            for (int i = 0; i + 1 < n; i++) {
                net.addEdge(i, i + 1, 50);
            }
            final int sink = n - 1;
            MaxFlowResult[] last = new MaxFlowResult[1];
            double median = medianMs(() -> last[0] = new EdmondsKarp().compute(net, 0, sink));
            System.out.printf("%-8d %-8d %-10d %.2f%n", n, net.edges().size(), last[0].maxFlow(), median);
        }
        System.out.println();
    }

    // ------------------------------------------------------------------ tries

    private static String randomWord(Random rnd, int minLen, int maxLen) {
        int len = minLen + rnd.nextInt(maxLen - minLen + 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append((char) ('a' + rnd.nextInt(26)));
        }
        return sb.toString();
    }

    private static void benchTrie() {
        System.out.println("== Prefix Trie vs linear scan (100,000 words, 500 prefix queries) ==");
        Random rnd = new Random(3);
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        while (unique.size() < 100_000) {
            unique.add(randomWord(rnd, 6, 12));
        }
        List<String> words = new ArrayList<>(unique);
        Trie trie = new Trie();
        for (String w : words) {
            trie.insert(w);
        }
        List<String> prefixes = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            prefixes.add(words.get(rnd.nextInt(words.size())).substring(0, 4));
        }
        long[] trieHits = new long[1];
        double trieMs = medianMs(() -> {
            long hits = 0;
            for (String p : prefixes) {
                hits += trie.wordsWithPrefix(p).size();
            }
            trieHits[0] = hits;
        });
        long[] scanHits = new long[1];
        double scanMs = medianMs(() -> {
            long hits = 0;
            for (String p : prefixes) {
                for (String w : words) {
                    if (w.startsWith(p)) {
                        hits++;
                    }
                }
            }
            scanHits[0] = hits;
        });
        System.out.printf("trie: %.2f ms   linear scan: %.2f ms   results match: %s%n%n",
                trieMs, scanMs, trieHits[0] == scanHits[0]);
    }

    private static boolean matches(String word, String pattern) {
        if (word.length() != pattern.length()) {
            return false;
        }
        for (int i = 0; i < word.length(); i++) {
            if (pattern.charAt(i) != '.' && pattern.charAt(i) != word.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static void benchWildcard() {
        System.out.println("== Wildcard dictionary vs naive scan (50,000 words, 200 patterns) ==");
        Random rnd = new Random(4);
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        while (unique.size() < 50_000) {
            unique.add(randomWord(rnd, 5, 8));
        }
        List<String> words = new ArrayList<>(unique);
        WordDictionary dict = new WordDictionary();
        for (String w : words) {
            dict.addWord(w);
        }
        List<String> patterns = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            char[] c = words.get(rnd.nextInt(words.size())).toCharArray();
            c[rnd.nextInt(c.length)] = '.';
            patterns.add(new String(c));
        }
        long[] dictHits = new long[1];
        double dictMs = medianMs(() -> {
            long hits = 0;
            for (String p : patterns) {
                hits += dict.findAll(p).size();
            }
            dictHits[0] = hits;
        });
        long[] scanHits = new long[1];
        double scanMs = medianMs(() -> {
            long hits = 0;
            for (String p : patterns) {
                for (String w : words) {
                    if (matches(w, p)) {
                        hits++;
                    }
                }
            }
            scanHits[0] = hits;
        });
        System.out.printf("dictionary: %.2f ms   naive scan: %.2f ms   results match: %s%n%n",
                dictMs, scanMs, dictHits[0] == scanHits[0]);
    }

    // ------------------------------------------------------------------ segment tree

    private static void benchSegmentTree() {
        System.out.println("== Segment tree vs naive scan (200,000 slots, 20,000 queries, 10,000 updates) ==");
        Random rnd = new Random(5);
        int n = 200_000;
        int[] data = new int[n];
        for (int i = 0; i < n; i++) {
            data[i] = rnd.nextInt(101);
        }
        SegmentTree segTree = new SegmentTree(data);
        for (int i = 0; i < 10_000; i++) {
            int idx = rnd.nextInt(n);
            int val = rnd.nextInt(101);
            segTree.update(idx, val);
            data[idx] = val;
        }
        int q = 20_000;
        int[][] ranges = new int[q][2];
        for (int i = 0; i < q; i++) {
            int a = rnd.nextInt(n);
            int b = rnd.nextInt(n);
            ranges[i][0] = Math.min(a, b);
            ranges[i][1] = Math.max(a, b);
        }
        long[] tree = new long[2];
        double treeMs = medianMs(() -> {
            long sum = 0;
            long max = 0;
            for (int[] r : ranges) {
                sum += segTree.rangeSum(r[0], r[1]);
                max += segTree.rangeMax(r[0], r[1]);
            }
            tree[0] = sum;
            tree[1] = max;
        });
        long[] naive = new long[2];
        double naiveMs = medianMs(() -> {
            long sum = 0;
            long max = 0;
            for (int[] r : ranges) {
                int s = 0;
                int m = Integer.MIN_VALUE;
                for (int i = r[0]; i <= r[1]; i++) {
                    s += data[i];
                    m = Math.max(m, data[i]);
                }
                sum += s;
                max += m;
            }
            naive[0] = sum;
            naive[1] = max;
        });
        System.out.printf("segment tree: %.2f ms   naive scan: %.2f ms   results match: %s%n%n",
                treeMs, naiveMs, tree[0] == naive[0] && tree[1] == naive[1]);
    }

    // ------------------------------------------------------------------ red-black tree

    private static void benchRedBlackTree() {
        System.out.println("== Red-black tree vs java.util.TreeMap (100,000 keys, remove 50,000) ==");
        Random rnd = new Random(6);
        List<Integer> keys = new ArrayList<>();
        for (int i = 0; i < 100_000; i++) {
            keys.add(i);
        }
        Collections.shuffle(keys, rnd);

        TreeMap<Integer, Integer> ref = new TreeMap<>();
        for (int k : keys) {
            ref.put(k, k);
        }
        for (int i = 0; i < 50_000; i++) {
            ref.remove(keys.get(i));
        }

        double[] insertMs = new double[RUNS];
        double[] removeMs = new double[RUNS];
        boolean validAfterInsert = true;
        boolean validAfterRemove = true;
        boolean same = true;
        int height = 0;
        for (int run = -1; run < RUNS; run++) { // run -1 is the warm-up
            RedBlackTree<Integer, Integer> rb = new RedBlackTree<>();
            long t0 = System.nanoTime();
            for (int k : keys) {
                rb.put(k, k);
            }
            long insertNanos = System.nanoTime() - t0;
            validAfterInsert &= rb.validate();
            height = rb.height();

            t0 = System.nanoTime();
            for (int i = 0; i < 50_000; i++) {
                rb.remove(keys.get(i));
            }
            long removeNanos = System.nanoTime() - t0;
            validAfterRemove &= rb.validate();
            same &= rb.size() == ref.size()
                    && rb.firstKey().equals(ref.firstKey())
                    && rb.lastKey().equals(ref.lastKey());
            if (run >= 0) {
                insertMs[run] = ms(insertNanos);
                removeMs[run] = ms(removeNanos);
            }
        }
        System.out.printf("insert: %.2f ms   remove: %.2f ms   height after insert: %d (log2 n = 16.6)%n",
                median(insertMs), median(removeMs), height);
        System.out.printf("invariants hold after insert: %s, after remove: %s, matches TreeMap: %s%n",
                validAfterInsert, validAfterRemove, same);
    }
}
