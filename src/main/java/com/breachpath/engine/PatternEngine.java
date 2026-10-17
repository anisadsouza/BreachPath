package com.breachpath.engine;

import com.breachpath.trie.WordDictionary;

import java.util.Collection;
import java.util.List;
import java.util.Locale;

/** Rule-matching engine: finds observed commands that match partially known patterns like "p.wershell". */
public class PatternEngine {
    private final WordDictionary dictionary = new WordDictionary();

    public PatternEngine(Collection<String> observedCommands) {
        for (String c : observedCommands) {
            if (c != null && !c.isBlank()) {
                dictionary.addWord(c.trim().toLowerCase(Locale.ROOT));
            }
        }
    }

    public List<String> match(String pattern) {
        return dictionary.findAll(pattern.toLowerCase(Locale.ROOT));
    }

    public int size() {
        return dictionary.size();
    }
}
