package com.breachpath.trie;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Prefix trie used to store indicators of compromise (domains, file paths, commands). */
public class Trie {
    private final TrieNode root = new TrieNode();
    private int size;

    /** Inserts a word; returns false if it was already present. */
    public boolean insert(String word) {
        requireNonEmpty(word);
        TrieNode node = root;
        for (int i = 0; i < word.length(); i++) {
            node = node.children.computeIfAbsent(word.charAt(i), c -> new TrieNode());
        }
        if (node.endOfWord) {
            return false;
        }
        node.endOfWord = true;
        size++;
        return true;
    }

    /** Exact lookup. */
    public boolean contains(String word) {
        TrieNode node = find(word);
        return node != null && node.endOfWord;
    }

    /** True if any stored word starts with the given prefix. */
    public boolean startsWith(String prefix) {
        return find(prefix) != null;
    }

    /** All stored words that start with {@code prefix}, in alphabetical order. */
    public List<String> wordsWithPrefix(String prefix) {
        List<String> result = new ArrayList<>();
        TrieNode node = find(prefix);
        if (node != null) {
            collect(node, new StringBuilder(prefix), result);
        }
        return result;
    }

    /** True if some stored word is a prefix of {@code text} (used for prefix rules such as a folder path). */
    public boolean containsPrefixOf(String text) {
        TrieNode node = root;
        for (int i = 0; i < text.length(); i++) {
            node = node.children.get(text.charAt(i));
            if (node == null) {
                return false;
            }
            if (node.endOfWord) {
                return true;
            }
        }
        return false;
    }

    /** Removes a word, pruning nodes that are no longer needed. Returns false if it was absent. */
    public boolean delete(String word) {
        if (word == null || !contains(word)) {
            return false;
        }
        delete(root, word, 0);
        size--;
        return true;
    }

    public int size() {
        return size;
    }

    private boolean delete(TrieNode node, String word, int i) {
        if (i == word.length()) {
            node.endOfWord = false;
            return node.children.isEmpty();
        }
        char c = word.charAt(i);
        TrieNode child = node.children.get(c);
        if (delete(child, word, i + 1)) {
            node.children.remove(c);
        }
        return !node.endOfWord && node.children.isEmpty();
    }

    private TrieNode find(String s) {
        if (s == null) {
            return null;
        }
        TrieNode node = root;
        for (int i = 0; i < s.length(); i++) {
            node = node.children.get(s.charAt(i));
            if (node == null) {
                return null;
            }
        }
        return node;
    }

    private void collect(TrieNode node, StringBuilder sb, List<String> out) {
        if (node.endOfWord) {
            out.add(sb.toString());
        }
        for (Map.Entry<Character, TrieNode> e : node.children.entrySet()) {
            sb.append(e.getKey());
            collect(e.getValue(), sb, out);
            sb.deleteCharAt(sb.length() - 1);
        }
    }

    private static void requireNonEmpty(String word) {
        if (word == null || word.isEmpty()) {
            throw new IllegalArgumentException("word must not be null or empty");
        }
    }
}
