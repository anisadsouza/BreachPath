package com.breachpath.trie;

import java.util.Map;
import java.util.TreeMap;

/** One node of a trie. A TreeMap keeps children sorted so results are deterministic. */
public class TrieNode {
    final Map<Character, TrieNode> children = new TreeMap<>();
    boolean endOfWord;
}
