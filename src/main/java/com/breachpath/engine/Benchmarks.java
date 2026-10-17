package com.breachpath.engine;

import com.breachpath.graph.BruteForceMinCut;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.FlowNetwork;
import com.breachpath.graph.FordFulkerson;
import com.breachpath.graph.MaxFlowResult;
import com.breachpath.rbtree.RedBlackTree;
import com.breachpath.segmenttree.SegmentTree;
import com.breachpath.trie.Trie;
import com.breachpath.trie.WordDictionary;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.TreeMap;

/** Correctness checks and timing experiments on synthetic data (fixed seeds, so repeatable). */
public final class Benchmarks {
    private Benchmarks() {
    }

    public static void runAll() {
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
        System.out.println("== Flow algorithms vs brute-force minimum cut (small random graphs) ==");
        Random rnd = new Random(1);
        EdmondsKarp ek = new EdmondsKarp();
        FordFulkerson ff = new FordFulkerson();
        int trials = 200;
        int mismatches = 0;
        for (int i = 0; i < trials; i++) {
            int n = 6 + rnd.nextInt(2);
            FlowNetwork net = randomNetwork(rnd, n, 6 + rnd.nextInt(8), 9);
            int brute = BruteForceMinCut.minCutCost(net, 0, n - 1, Integer.MAX_VALUE);
            MaxFlowResult a = ek.compute(net, 0, n - 1);
            MaxFlowResult b = ff.compute(net, 0, n - 1);
            if (a.maxFlow() != brute || b.maxFlow() != brute
                    || a.cutCost() != brute || b.cutCost() != brute) {
                mismatches++;
            }
        }
        System.out.printf("%d random graphs checked, mismatches: %d%n%n", trials, mismatches);
    }

    private static void benchFlows() {
        System.out.println("== Max flow: Edmonds-Karp vs Ford-Fulkerson (generated graphs) ==");
        System.out.printf("%-8s %-8s %-10s %-14s %-14s %-6s%n",
                "nodes", "edges", "max flow", "EK (ms)", "FF (ms)", "match");
        Random rnd = new Random(2);
        for (int n : new int[]{100, 200, 400}) {
            FlowNetwork net = randomNetwork(rnd, n, n * 5, 100);
            for (int i = 0; i + 1 < n; i++) {
                net.addEdge(i, i + 1, 50);
            }
            MaxFlowResult a = new EdmondsKarp().compute(net, 0, n - 1);
            MaxFlowResult b = new FordFulkerson().compute(net, 0, n - 1);
            System.out.printf("%-8d %-8d %-10d %-14.2f %-14.2f %-6s%n", n, net.edges().size(),
                    a.maxFlow(), ms(a.nanos()), ms(b.nanos()), a.maxFlow() == b.maxFlow());
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
        long t0 = System.nanoTime();
        long trieHits = 0;
        for (String p : prefixes) {
            trieHits += trie.wordsWithPrefix(p).size();
        }
        long trieNanos = System.nanoTime() - t0;

        t0 = System.nanoTime();
        long scanHits = 0;
        for (String p : prefixes) {
            for (String w : words) {
                if (w.startsWith(p)) {
                    scanHits++;
                }
            }
        }
        long scanNanos = System.nanoTime() - t0;
        System.out.printf("trie: %.2f ms   linear scan: %.2f ms   results match: %s%n%n",
                ms(trieNanos), ms(scanNanos), trieHits == scanHits);
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
        long t0 = System.nanoTime();
        long dictHits = 0;
        for (String p : patterns) {
            dictHits += dict.findAll(p).size();
        }
        long dictNanos = System.nanoTime() - t0;

        t0 = System.nanoTime();
        long scanHits = 0;
        for (String p : patterns) {
            for (String w : words) {
                if (matches(w, p)) {
                    scanHits++;
                }
            }
        }
        long scanNanos = System.nanoTime() - t0;
        System.out.printf("dictionary: %.2f ms   naive scan: %.2f ms   results match: %s%n%n",
                ms(dictNanos), ms(scanNanos), dictHits == scanHits);
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
        SegmentTree tree = new SegmentTree(data);
        for (int i = 0; i < 10_000; i++) {
            int idx = rnd.nextInt(n);
            int val = rnd.nextInt(101);
            tree.update(idx, val);
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
        long t0 = System.nanoTime();
        long treeSum = 0;
        long treeMax = 0;
        for (int[] r : ranges) {
            treeSum += tree.rangeSum(r[0], r[1]);
            treeMax += tree.rangeMax(r[0], r[1]);
        }
        long treeNanos = System.nanoTime() - t0;

        t0 = System.nanoTime();
        long naiveSum = 0;
        long naiveMax = 0;
        for (int[] r : ranges) {
            int s = 0;
            int m = Integer.MIN_VALUE;
            for (int i = r[0]; i <= r[1]; i++) {
                s += data[i];
                m = Math.max(m, data[i]);
            }
            naiveSum += s;
            naiveMax += m;
        }
        long naiveNanos = System.nanoTime() - t0;
        System.out.printf("segment tree: %.2f ms   naive scan: %.2f ms   results match: %s%n%n",
                ms(treeNanos), ms(naiveNanos), treeSum == naiveSum && treeMax == naiveMax);
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

        RedBlackTree<Integer, Integer> rb = new RedBlackTree<>();
        long t0 = System.nanoTime();
        for (int k : keys) {
            rb.put(k, k);
        }
        long insertNanos = System.nanoTime() - t0;
        boolean validAfterInsert = rb.validate();
        int height = rb.height();

        TreeMap<Integer, Integer> ref = new TreeMap<>();
        for (int k : keys) {
            ref.put(k, k);
        }
        t0 = System.nanoTime();
        for (int i = 0; i < 50_000; i++) {
            rb.remove(keys.get(i));
            ref.remove(keys.get(i));
        }
        long removeNanos = System.nanoTime() - t0;

        boolean same = rb.size() == ref.size()
                && rb.firstKey().equals(ref.firstKey())
                && rb.lastKey().equals(ref.lastKey());
        System.out.printf("insert: %.2f ms   remove: %.2f ms   height after insert: %d (log2 n = 16.6)%n",
                ms(insertNanos), ms(removeNanos), height);
        System.out.printf("invariants hold after insert: %s, after remove: %s, matches TreeMap: %s%n",
                validAfterInsert, rb.validate(), same);
    }
}
