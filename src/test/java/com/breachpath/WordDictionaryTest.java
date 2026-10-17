package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.trie.WordDictionary;
import java.util.List;
import org.junit.jupiter.api.Test;

class WordDictionaryTest {

    private static WordDictionary sample() {
        WordDictionary d = new WordDictionary();
        for (String w : new String[]{"power", "pewer", "bad", "dad", "mad"}) {
            d.addWord(w);
        }
        return d;
    }

    @Test
    void dotMatchesExactlyOneCharacter() {
        WordDictionary d = sample();
        assertTrue(d.search("pow.r"));
        assertTrue(d.search("power"));
        assertTrue(d.search("b.."));
        assertTrue(d.search("..."));
        assertFalse(d.search("pow..r"));
        assertFalse(d.search("pow."));
        assertFalse(d.search("pxwer"));
    }

    @Test
    void emptyPatternMatchesNothing() {
        assertFalse(sample().search(""));
        assertEquals(List.of(), sample().findAll(""));
    }

    @Test
    void findAllReturnsSortedMatches() {
        assertEquals(List.of("pewer", "power"), sample().findAll("p.wer"));
        assertEquals(List.of("bad", "dad", "mad"), sample().findAll(".ad"));
    }

    @Test
    void duplicateWordsCountOnce() {
        WordDictionary d = new WordDictionary();
        d.addWord("abc");
        d.addWord("abc");
        assertEquals(1, d.size());
    }
}
