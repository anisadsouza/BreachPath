package com.breachpath.trie;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Word dictionary with wildcard search. In a query pattern, '.' stands for exactly one
 * unknown character, so "pow.r" matches "power".
 */
public class WordDictionary {
    private final TrieNode root = new TrieNode();
    private int size;

    public void addWord(String word) {
        if (word == null || word.isEmpty()) {
            throw new IllegalArgumentException("word must not be null or empty");
        }
        TrieNode node = root;
        for (int i = 0; i < word.length(); i++) {
            node = node.children.computeIfAbsent(word.charAt(i), c -> new TrieNode());
        }
        if (!node.endOfWord) {
            node.endOfWord = true;
            size++;
        }
    }

    /** True if at least one stored word matches the pattern. An empty pattern matches nothing. */
    public boolean search(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }
        return search(root, pattern, 0);
    }

    /** Every stored word matching the pattern, in alphabetical order. */
    public List<String> findAll(String pattern) {
        List<String> out = new ArrayList<>();
        if (pattern != null && !pattern.isEmpty()) {
            findAll(root, pattern, 0, new StringBuilder(), out);
        }
        return out;
    }

    public int size() {
        return size;
    }

    private boolean search(TrieNode node, String p, int i) {
        if (i == p.length()) {
            return node.endOfWord;
        }
        char ch = p.charAt(i);
        if (ch == '.') {
            for (TrieNode child : node.children.values()) {
                if (search(child, p, i + 1)) {
                    return true;
                }
            }
            return false;
        }
        TrieNode child = node.children.get(ch);
        return child != null && search(child, p, i + 1);
    }

    private void findAll(TrieNode node, String p, int i, StringBuilder sb, List<String> out) {
        if (i == p.length()) {
            if (node.endOfWord) {
                out.add(sb.toString());
            }
            return;
        }
        char ch = p.charAt(i);
        if (ch == '.') {
            for (Map.Entry<Character, TrieNode> e : node.children.entrySet()) {
                sb.append(e.getKey());
                findAll(e.getValue(), p, i + 1, sb, out);
                sb.deleteCharAt(sb.length() - 1);
            }
        } else {
            TrieNode child = node.children.get(ch);
            if (child != null) {
                sb.append(ch);
                findAll(child, p, i + 1, sb, out);
                sb.deleteCharAt(sb.length() - 1);
            }
        }
    }
}
