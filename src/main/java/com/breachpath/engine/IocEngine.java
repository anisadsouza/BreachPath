package com.breachpath.engine;

import com.breachpath.trie.Trie;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Indicator-of-compromise search engine built on two tries: one for exact indicators and one for
 * prefix rules (written with a trailing '*' in the IOC file).
 */
public class IocEngine {
    private final Trie exact = new Trie();
    private final Trie prefixRules = new Trie();

    public static IocEngine fromLines(List<String> lines) {
        IocEngine engine = new IocEngine();
        for (String line : lines) {
            String s = line.trim().toLowerCase(Locale.ROOT);
            if (s.endsWith("*")) {
                engine.prefixRules.insert(s.substring(0, s.length() - 1));
            } else {
                engine.exact.insert(s);
            }
        }
        return engine;
    }

    /** True if the indicator equals a known IOC or starts with a known prefix rule. */
    public boolean isKnownIndicator(String indicator) {
        if (indicator == null || indicator.isEmpty()) {
            return false;
        }
        String s = indicator.toLowerCase(Locale.ROOT);
        return exact.contains(s) || prefixRules.containsPrefixOf(s);
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
