package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.rbtree.RedBlackTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class RedBlackTreeTest {

    @Test
    void emptyTree() {
        RedBlackTree<Integer, String> t = new RedBlackTree<>();
        assertTrue(t.isEmpty());
        assertTrue(t.validate());
        assertNull(t.firstKey());
        assertNull(t.lastKey());
        assertNull(t.get(1));
        assertFalse(t.remove(1));
    }

    @Test
    void putGetAndReplace() {
        RedBlackTree<Integer, String> t = new RedBlackTree<>();
        assertTrue(t.put(5, "five"));
        assertFalse(t.put(5, "FIVE"));
        assertEquals("FIVE", t.get(5));
        assertEquals(1, t.size());
    }

    @Test
    void sortedInsertionStaysBalanced() {
        RedBlackTree<Integer, Integer> t = new RedBlackTree<>();
        for (int i = 0; i < 1000; i++) {
            t.put(i, i);
            assertTrue(t.validate());
        }
        assertTrue(t.height() <= 2 * 11);
        assertEquals(0, t.firstKey());
        assertEquals(999, t.lastKey());
    }

    @Test
    void randomInsertAndDeleteMatchTreeMap() {
        Random rnd = new Random(21);
        RedBlackTree<Integer, Integer> t = new RedBlackTree<>();
        TreeMap<Integer, Integer> ref = new TreeMap<>();
        List<Integer> keys = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            keys.add(i);
        }
        Collections.shuffle(keys, rnd);
        for (int k : keys) {
            t.put(k, k);
            ref.put(k, k);
            assertTrue(t.validate());
        }
        Collections.shuffle(keys, rnd);
        for (int i = 0; i < 400; i++) {
            int k = keys.get(i);
            assertTrue(t.remove(k));
            ref.remove(k);
            assertTrue(t.validate());
            assertEquals(ref.size(), t.size());
        }
        assertEquals(new ArrayList<>(ref.keySet()), t.ascendingKeys());
        assertEquals(ref.firstKey(), t.firstKey());
        assertEquals(ref.lastKey(), t.lastKey());
    }

    @Test
    void descendingValuesHonoursLimit() {
        RedBlackTree<Integer, String> t = new RedBlackTree<>();
        for (int i = 1; i <= 5; i++) {
            t.put(i, "v" + i);
        }
        assertEquals(List.of("v5", "v4", "v3"), t.descendingValues(3));
        assertEquals(5, t.descendingValues(100).size());
    }

    @Test
    void removeEverythingLeavesEmptyValidTree() {
        RedBlackTree<Integer, Integer> t = new RedBlackTree<>();
        for (int i = 0; i < 50; i++) {
            t.put(i, i);
        }
        for (int i = 0; i < 50; i++) {
            assertTrue(t.remove(i));
        }
        assertTrue(t.isEmpty());
        assertTrue(t.validate());
    }
}
