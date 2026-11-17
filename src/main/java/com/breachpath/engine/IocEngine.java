package com.breachpath.engine;

import com.breachpath.bloom.BloomFilter;
import com.breachpath.trie.Trie;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Indicator-of-compromise search engine built on two tries (exact indicators and prefix rules,
 * written with a trailing '*' in the IOC file) and a Bloom filter that screens exact lookups.
 *
 * <p>Screening: a Bloom filter holds every exact indicator. For each lookup the filter is asked
 * first. "Definitely absent" is final and the trie is not consulted. "Possibly present" is never
 * trusted: the trie confirms it, so a Bloom false positive cannot flag a clean indicator. The
 * answers of {@link #isKnownIndicator} are therefore identical to a trie-only engine; the filter
 * only avoids authoritative lookups for indicators that are certainly not in the feed.
 */
public class IocEngine {
    /** Target false-positive rate of the screening filter. */
    public static final double BLOOM_TARGET_RATE = 0.01;

    private final Trie exact = new Trie();
    private final Trie prefixRules = new Trie();
    private BloomFilter bloom = new BloomFilter(1, BLOOM_TARGET_RATE);

    private final AtomicLong lookups = new AtomicLong();
    private final AtomicLong bloomRejects = new AtomicLong();
    private final AtomicLong bloomPasses = new AtomicLong();
    private final AtomicLong bloomFalsePositives = new AtomicLong();

    /** How one indicator was screened. */
    public record Screening(String indicator, boolean bloomPossible, boolean exactConfirmed,
                            boolean prefixRuleMatch, boolean known) {
        /** True when the filter said "possibly present" but the trie did not confirm it. */
        public boolean bloomFalsePositive() {
            return bloomPossible && !exactConfirmed;
        }
    }

    /** Filter parameters and the running screening counters. */
    public record BloomStats(long bitSize, int hashCount, int items, double targetRate,
                             double estimatedRate, double fillRatio,
                             long lookups, long bloomRejects, long bloomPasses, long falsePositives) {
        /** Share of screened lookups that never needed the authoritative trie (0 when none were made). */
        public double lookupsAvoided() {
            return lookups == 0 ? 0.0 : (double) bloomRejects / lookups;
        }
    }

    public static IocEngine fromLines(List<String> lines) {
        IocEngine engine = new IocEngine();
        List<String> exactLines = new ArrayList<>();
        for (String line : lines) {
            String s = line.trim().toLowerCase(Locale.ROOT);
            if (s.endsWith("*")) {
                engine.prefixRules.insert(s.substring(0, s.length() - 1));
            } else {
                exactLines.add(s);
            }
        }
        engine.bloom = new BloomFilter(Math.max(1, exactLines.size()), BLOOM_TARGET_RATE);
        for (String s : exactLines) {
            engine.exact.insert(s);
            engine.bloom.add(s);
        }
        return engine;
    }

    /** True if the indicator equals a known IOC or starts with a known prefix rule. */
    public boolean isKnownIndicator(String indicator) {
        return screen(indicator).known();
    }

    /**
     * Screens one indicator and reports each step: what the Bloom filter said, whether the trie
     * confirmed it, and whether a prefix rule matched. Blank or null input is never known.
     */
    public Screening screen(String indicator) {
        if (indicator == null || indicator.isEmpty()) {
            return new Screening(indicator == null ? "" : indicator, false, false, false, false);
        }
        String s = indicator.toLowerCase(Locale.ROOT);
        lookups.incrementAndGet();
        boolean possible = bloom.mightContain(s);
        boolean confirmed = false;
        if (possible) {
            bloomPasses.incrementAndGet();
            confirmed = exact.contains(s);
            if (!confirmed) {
                bloomFalsePositives.incrementAndGet();
            }
        } else {
            bloomRejects.incrementAndGet();
        }
        boolean rule = prefixRules.containsPrefixOf(s);
        return new Screening(indicator, possible, confirmed, rule, confirmed || rule);
    }

    /** Filter parameters and counters accumulated by {@link #screen} / {@link #isKnownIndicator}. */
    public BloomStats bloomStats() {
        return new BloomStats(bloom.bitSize(), bloom.hashCount(), (int) bloom.additions(),
                bloom.targetFalsePositiveRate(), bloom.estimatedFalsePositiveRate(), bloom.fillRatio(),
                lookups.get(), bloomRejects.get(), bloomPasses.get(), bloomFalsePositives.get());
    }

    /** Investigator search: stored IOCs (and prefix rules, shown with '*') starting with the prefix. */
    public List<String> search(String prefix) {
        String p = prefix.toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>(exact.wordsWithPrefix(p));
        for (String rule : prefixRules.wordsWithPrefix(p)) {
            out.add(rule + "*");
        }
        return out;
    }

    public int size() {
        return exact.size() + prefixRules.size();
    }
}