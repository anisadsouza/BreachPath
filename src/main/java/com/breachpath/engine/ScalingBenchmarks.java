package com.breachpath.engine;

import com.breachpath.bloom.BloomFilter;
import com.breachpath.graph.BruteForceMinCut;
import com.breachpath.graph.EdmondsKarp;
import com.breachpath.graph.FlowNetwork;
import com.breachpath.rbtree.RedBlackTree;
import com.breachpath.segmenttree.SegmentTree;
import com.breachpath.select.RandomizedSelect;
import com.breachpath.trie.Trie;
import com.breachpath.trie.WordDictionary;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

/**
 * Scaling experiments: every technique is timed at three increasing input sizes against a plain
 * baseline, on seeded synthetic data. Each time is the median of {@link Benchmarks#RUNS} runs after
 * one warm-up run. Every row also records whether the technique and the baseline produced the same
 * answer, so a speed-up is never reported for a wrong result.
 */
public final class ScalingBenchmarks {

    /** QUICK finishes in a few seconds (used by the web API); FULL uses larger inputs. */
    public enum Profile { QUICK, FULL }

    /**
     * One input size.
     *
     * @param size       label such as "100,000 words"
     * @param fastMs     median time of the technique
     * @param baselineMs median time of the baseline
     * @param match      technique and baseline gave the same answer
     * @param detail     extra measured facts for this size (may be empty)
     */
    public record Row(String size, double fastMs, double baselineMs, boolean match, String detail) {
        public double speedup() {
            return baselineMs / Math.max(fastMs, 0.001);
        }
    }

    /** One technique, its baseline, three or more sizes, and a plain statement of when it helps. */
    public record Experiment(String id, String technique, String baseline, String workload,
                             List<Row> rows, String conclusion) {
        public boolean allMatch() {
            return rows.stream().allMatch(Row::match);
        }
    }

    private ScalingBenchmarks() {
    }

    public static List<Experiment> run(Profile profile) {
        boolean full = profile == Profile.FULL;
        List<Experiment> out = new ArrayList<>();
        out.add(quickselect(full ? new int[]{10_000, 100_000, 1_000_000} : new int[]{10_000, 50_000, 200_000}));
        out.add(bloom(full ? new int[]{1_000, 10_000, 100_000} : new int[]{1_000, 10_000, 50_000}));
        out.add(trie(full ? new int[]{10_000, 50_000, 100_000} : new int[]{5_000, 20_000, 50_000}));
        out.add(wildcard(full ? new int[]{5_000, 20_000, 50_000} : new int[]{2_000, 10_000, 25_000}));
        out.add(segmentTree(full ? new int[]{10_000, 50_000, 200_000} : new int[]{5_000, 25_000, 100_000}));
        out.add(maxFlow(new int[]{10, 16, 22}));
        out.add(redBlack(full ? new int[]{10_000, 50_000, 100_000} : new int[]{5_000, 20_000, 50_000}));
        return out;
    }

    /** Prints the experiments as aligned text tables. */
    public static void print(List<Experiment> experiments) {
        System.out.println("Each time is the median of " + Benchmarks.RUNS + " runs after one warm-up run.");
        for (Experiment e : experiments) {
            System.out.println();
            System.out.println("== " + e.technique() + " vs " + e.baseline() + " (" + e.workload() + ") ==");
            System.out.printf(Locale.ROOT, "%-18s %12s %14s %9s  %-7s %s%n",
                    "size", "technique ms", "baseline ms", "speed-up", "match", "detail");
            for (Row r : e.rows()) {
                System.out.printf(Locale.ROOT, "%-18s %12.2f %14.2f %8.1fx  %-7s %s%n",
                        r.size(), r.fastMs(), r.baselineMs(), r.speedup(), r.match(), r.detail());
            }
            System.out.println(e.conclusion());
        }
    }

    // ------------------------------------------------------------------ timing

    private static double medianMs(Runnable task) {
        task.run();
        double[] times = new double[Benchmarks.RUNS];
        for (int i = 0; i < times.length; i++) {
            long start = System.nanoTime();
            task.run();
            times[i] = (System.nanoTime() - start) / 1_000_000.0;
        }
        return Benchmarks.median(times);
    }

    private static String fmt(int n) {
        return String.format(Locale.ROOT, "%,d", n);
    }

    private static String randomString(Random rnd, int minLen, int maxLen, String alphabet) {
        int len = minLen + rnd.nextInt(maxLen - minLen + 1);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String HOSTCHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";

    // ------------------------------------------------------------------ randomized quickselect

    private static Experiment quickselect(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        for (int n : sizes) {
            Random rnd = new Random(11L + n);
            int[] data = new int[n];
            for (int i = 0; i < n; i++) {
                data[i] = rnd.nextInt(1_000_000);
            }
            int rank = (int) Math.ceil(0.90 * n) - 1;
            long[] cmp = new long[1];
            int[] sel = new int[1];
            double fast = medianMs(() -> {
                RandomizedSelect.Result r = RandomizedSelect.kthSmallest(data, rank, new Random(7));
                sel[0] = r.value();
                cmp[0] = r.comparisons();
            });
            int[] ref = new int[1];
            double base = medianMs(() -> {
                int[] copy = data.clone();
                Arrays.sort(copy);
                ref[0] = copy[rank];
            });
            rows.add(new Row(fmt(n) + " values", fast, base, sel[0] == ref[0],
                    String.format(Locale.ROOT, "%.2f comparisons per element", (double) cmp[0] / n)));
        }
        return new Experiment("quickselect", "Randomized Quickselect (90th percentile)",
                "full sort then index", "random integers, one percentile query", rows,
                "Expected O(n) comparisons (a small constant number per element that does not grow with n; it varies "
                        + "a little with pivot luck) against "
                        + "O(n log n) for sorting. It helps when you need one or a few order statistics; "
                        + "for many queries on the same data, sort once instead.");
    }

    // ------------------------------------------------------------------ bloom filter

    private static Experiment bloom(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        int queries = 200_000;
        for (int n : sizes) {
            Random rnd = new Random(21L + n);
            LinkedHashSet<String> members = new LinkedHashSet<>();
            while (members.size() < n) {
                members.add(randomString(rnd, 12, 30, HOSTCHARS));
            }
            List<String> memberList = new ArrayList<>(members);
            Trie trie = new Trie();
            BloomFilter filter = new BloomFilter(n, IocEngine.BLOOM_TARGET_RATE);
            for (String m : memberList) {
                trie.insert(m);
                filter.add(m);
            }
            // Half the queries are real indicators, half are clean strings that are not in the feed.
            List<String> probes = new ArrayList<>(queries);
            Set<String> clean = new HashSet<>();
            while (clean.size() < queries / 2) {
                String s = randomString(rnd, 12, 30, HOSTCHARS);
                if (!members.contains(s)) {
                    clean.add(s);
                }
            }
            for (int i = 0; i < queries / 2; i++) {
                probes.add(memberList.get(rnd.nextInt(memberList.size())));
            }
            probes.addAll(clean);
            Collections.shuffle(probes, rnd);

            long[] screenedHits = new long[1];
            long[] bloomPasses = new long[1];
            double screened = medianMs(() -> {
                long hits = 0;
                long passes = 0;
                for (String p : probes) {
                    if (filter.mightContain(p)) {
                        passes++;
                        if (trie.contains(p)) {
                            hits++;
                        }
                    }
                }
                screenedHits[0] = hits;
                bloomPasses[0] = passes;
            });
            long[] trieHits = new long[1];
            double trieOnly = medianMs(() -> {
                long hits = 0;
                for (String p : probes) {
                    if (trie.contains(p)) {
                        hits++;
                    }
                }
                trieHits[0] = hits;
            });
            long falsePositives = bloomPasses[0] - screenedHits[0];
            double measured = (double) falsePositives / (queries / 2.0);
            double avoided = 1.0 - (double) bloomPasses[0] / queries;
            rows.add(new Row(fmt(n) + " indicators", screened, trieOnly, screenedHits[0] == trieHits[0],
                    String.format(Locale.ROOT,
                            "false-positive rate %.2f%% (target %.1f%%), %.0f%% of lookups skipped the trie, filter %.1f KB",
                            measured * 100, IocEngine.BLOOM_TARGET_RATE * 100, avoided * 100,
                            filter.bitSize() / 8.0 / 1024.0)));
        }
        return new Experiment("bloom", "Bloom filter screen + exact trie confirmation",
                "trie lookup only", "200,000 lookups, half real indicators and half clean", rows,
                "Answers are identical because every 'possibly present' is confirmed by the trie. "
                        + "The filter never gives a false negative and its false-positive rate stays near the "
                        + "target. Against an in-memory trie it saves little or no time: a miss in a trie is "
                        + "already cheap. It helps when the authoritative check is expensive (a disk, remote "
                        + "feed or database lookup), because about half of these lookups never reach it. The filter "
                        + "itself needs only about 10 bits per indicator, small enough to keep in memory when "
                        + "the full list lives elsewhere.");
    }

    // ------------------------------------------------------------------ prefix trie

    private static Experiment trie(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        int queries = 300;
        for (int n : sizes) {
            Random rnd = new Random(31L + n);
            LinkedHashSet<String> unique = new LinkedHashSet<>();
            while (unique.size() < n) {
                unique.add(randomString(rnd, 6, 12, LOWER));
            }
            List<String> words = new ArrayList<>(unique);
            Trie trie = new Trie();
            for (String w : words) {
                trie.insert(w);
            }
            List<String> prefixes = new ArrayList<>();
            for (int i = 0; i < queries; i++) {
                prefixes.add(words.get(rnd.nextInt(words.size())).substring(0, 4));
            }
            long[] a = new long[1];
            double fast = medianMs(() -> {
                long hits = 0;
                for (String p : prefixes) {
                    hits += trie.wordsWithPrefix(p).size();
                }
                a[0] = hits;
            });
            long[] b = new long[1];
            double base = medianMs(() -> {
                long hits = 0;
                for (String p : prefixes) {
                    for (String w : words) {
                        if (w.startsWith(p)) {
                            hits++;
                        }
                    }
                }
                b[0] = hits;
            });
            rows.add(new Row(fmt(n) + " words", fast, base, a[0] == b[0], fmt((int) a[0]) + " matches in total"));
        }
        return new Experiment("trie", "Prefix trie", "linear scan with startsWith",
                queries + " four-letter prefix queries", rows,
                "A prefix query costs O(prefix length + matches) instead of O(words x prefix length), so the "
                        + "gap widens as the indicator list grows. For a handful of indicators a plain list is as good.");
    }

    // ------------------------------------------------------------------ wildcard dictionary

    private static boolean wildMatch(String word, String pattern) {
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

    private static Experiment wildcard(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        int queries = 100;
        for (int n : sizes) {
            Random rnd = new Random(41L + n);
            LinkedHashSet<String> unique = new LinkedHashSet<>();
            while (unique.size() < n) {
                unique.add(randomString(rnd, 5, 8, LOWER));
            }
            List<String> words = new ArrayList<>(unique);
            WordDictionary dict = new WordDictionary();
            for (String w : words) {
                dict.addWord(w);
            }
            List<String> patterns = new ArrayList<>();
            for (int i = 0; i < queries; i++) {
                char[] c = words.get(rnd.nextInt(words.size())).toCharArray();
                c[rnd.nextInt(c.length)] = '.';
                patterns.add(new String(c));
            }
            long[] a = new long[1];
            double fast = medianMs(() -> {
                long hits = 0;
                for (String p : patterns) {
                    hits += dict.findAll(p).size();
                }
                a[0] = hits;
            });
            long[] b = new long[1];
            double base = medianMs(() -> {
                long hits = 0;
                for (String p : patterns) {
                    for (String w : words) {
                        if (wildMatch(w, p)) {
                            hits++;
                        }
                    }
                }
                b[0] = hits;
            });
            rows.add(new Row(fmt(n) + " words", fast, base, a[0] == b[0], fmt((int) a[0]) + " matches in total"));
        }
        return new Experiment("wildcard", "Wildcard dictionary (trie with '.')", "naive scan of every word",
                queries + " patterns with one unknown character", rows,
                "The trie only follows branches that can still match, so a pattern with one '.' touches a small "
                        + "part of the dictionary. Patterns that start with '.' fan out at the root and lose most of the advantage.");
    }

    // ------------------------------------------------------------------ segment tree

    private static Experiment segmentTree(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        int queries = 10_000;
        int updates = 5_000;
        for (int n : sizes) {
            Random rnd = new Random(51L + n);
            int[] data = new int[n];
            for (int i = 0; i < n; i++) {
                data[i] = rnd.nextInt(101);
            }
            SegmentTree tree = new SegmentTree(data);
            for (int i = 0; i < updates; i++) {
                int idx = rnd.nextInt(n);
                int val = rnd.nextInt(101);
                tree.update(idx, val);
                data[idx] = val;
            }
            int[][] ranges = new int[queries][2];
            for (int i = 0; i < queries; i++) {
                int x = rnd.nextInt(n);
                int y = rnd.nextInt(n);
                ranges[i][0] = Math.min(x, y);
                ranges[i][1] = Math.max(x, y);
            }
            long[] a = new long[2];
            double fast = medianMs(() -> {
                long sum = 0;
                long max = 0;
                for (int[] r : ranges) {
                    sum += tree.rangeSum(r[0], r[1]);
                    max += tree.rangeMax(r[0], r[1]);
                }
                a[0] = sum;
                a[1] = max;
            });
            long[] b = new long[2];
            double base = medianMs(() -> {
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
                b[0] = sum;
                b[1] = max;
            });
            rows.add(new Row(fmt(n) + " slots", fast, base, a[0] == b[0] && a[1] == b[1],
                    fmt(queries) + " range sum + max queries after " + fmt(updates) + " updates"));
        }
        return new Experiment("segment", "Segment tree (range sum and max)", "naive scan of the range",
                queries + " random ranges", rows,
                "A range query and a point update both cost O(log n); a scan costs O(range length). "
                        + "On a 24-slot alert log the two are equal, so the tree pays off only on long logs.");
    }

    // ------------------------------------------------------------------ max flow

    /** @param edgeCounts edge counts of the test networks; brute force enumerates 2^edges cuts, so 22 is its limit */
    private static Experiment maxFlow(int[] edgeCounts) {
        List<Row> rows = new ArrayList<>();
        for (int m : edgeCounts) {
            int n = m / 2 + 1;
            Random rnd = new Random(61L + m);
            FlowNetwork net = new FlowNetwork(n);
            for (int i = 0; i + 1 < n; i++) {
                net.addEdge(i, i + 1, 1 + rnd.nextInt(9));
            }
            int guard = 0;
            while (net.edges().size() < m && guard++ < 10_000) {
                int u = rnd.nextInt(n);
                int v = rnd.nextInt(n);
                if (u != v) {
                    net.addEdge(u, v, 1 + rnd.nextInt(9));
                }
            }
            int edges = net.edges().size();
            int[] a = new int[1];
            double fast = medianMs(() -> a[0] = new EdmondsKarp().compute(net, 0, n - 1).cutCost());
            int[] b = new int[1];
            double base = medianMs(() -> b[0] = BruteForceMinCut.minCutCost(net, 0, n - 1, Integer.MAX_VALUE));
            rows.add(new Row(n + " nodes, " + edges + " edges", fast, base, a[0] == b[0],
                    "min cut cost " + a[0] + "; brute force checks " + fmt(1 << edges) + " edge subsets"));
        }
        return new Experiment("maxflow", "Edmonds-Karp max flow / min cut", "brute-force minimum cut",
                "random networks, up to the brute force limit of 22 edges", rows,
                "Edmonds-Karp runs in O(V E^2) and matches the exhaustive answer on every network. The brute "
                        + "force doubles with every extra edge, so it cannot go past 22 edges, while Edmonds-Karp "
                        + "handles 400 nodes and 2,400 edges in milliseconds (see the console benchmark).");
    }

    // ------------------------------------------------------------------ red-black tree

    private static Experiment redBlack(int[] sizes) {
        List<Row> rows = new ArrayList<>();
        for (int n : sizes) {
            Random rnd = new Random(71L + n);
            List<Integer> keys = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                keys.add(i);
            }
            Collections.shuffle(keys, rnd);
            boolean[] ok = {true};
            int[] height = new int[1];
            double fast = medianMs(() -> {
                RedBlackTree<Integer, Integer> rb = new RedBlackTree<>();
                for (int k : keys) {
                    rb.put(k, k);
                }
                for (int i = 0; i < n / 2; i++) {
                    rb.remove(keys.get(i));
                }
                height[0] = rb.height();
                ok[0] = rb.validate() && rb.size() == n - n / 2;
            });
            double base = medianMs(() -> {
                TreeMap<Integer, Integer> ref = new TreeMap<>();
                for (int k : keys) {
                    ref.put(k, k);
                }
                for (int i = 0; i < n / 2; i++) {
                    ref.remove(keys.get(i));
                }
            });
            rows.add(new Row(fmt(n) + " keys", fast, base, ok[0],
                    "invariants hold; tree height after inserts and removals " + height[0]));
        }
        return new Experiment("rbtree", "Red-black tree (insert + remove half)", "java.util.TreeMap",
                "random keys", rows,
                "TreeMap is itself a red-black tree, so similar timings are the expected result; the point is "
                        + "that the own implementation keeps every red-black invariant and O(log n) height.");
    }
}