package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.trie.Trie;
import java.util.List;
import org.junit.jupiter.api.Test;

class TrieTest {

    @Test
    void insertAndExactLookup() {
        Trie t = new Trie();
        assertTrue(t.insert("evil.com"));
        assertFalse(t.insert("evil.com"));
        assertTrue(t.contains("evil.com"));
        assertFalse(t.contains("evil"));
        assertFalse(t.contains("evil.com/x"));
        assertEquals(1, t.size());
    }

    @Test
    void prefixSearchReturnsSortedWords() {
        Trie t = new Trie();
        for (String w : new String[]{"cmd", "cmd.exe", "curl", "powershell"}) {
            t.insert(w);
        }
        assertTrue(t.startsWith("cm"));
        assertFalse(t.startsWith("x"));
        assertEquals(List.of("cmd", "cmd.exe"), t.wordsWithPrefix("cm"));
        assertEquals(List.of(), t.wordsWithPrefix("zzz"));
        assertEquals(4, t.wordsWithPrefix("").size());
    }

    @Test
    void containsPrefixOfMatchesStoredRules() {
        Trie t = new Trie();
        t.insert("/var/tmp/");
        assertTrue(t.containsPrefixOf("/var/tmp/dump.bin"));
        assertFalse(t.containsPrefixOf("/var/log/syslog"));
        assertFalse(t.containsPrefixOf(""));
    }

    @Test
    void deleteKeepsOtherWords() {
        Trie t = new Trie();
        t.insert("car");
        t.insert("card");
        assertTrue(t.delete("card"));
        assertFalse(t.contains("card"));
        assertTrue(t.contains("car"));
        assertFalse(t.delete("card"));
        assertTrue(t.delete("car"));
        assertFalse(t.startsWith("c"));
        assertEquals(0, t.size());
    }

    @Test
    void rejectsEmptyWord() {
        assertThrows(IllegalArgumentException.class, () -> new Trie().insert(""));
    }
}
