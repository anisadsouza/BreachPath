package com.breachpath.rbtree;

import java.util.ArrayList;
import java.util.List;

/**
 * Red-black tree (self-balancing BST) following the classic CLRS algorithms,
 * with insert, update-by-key, delete, lookup, min/max and an invariant checker.
 */
public class RedBlackTree<K extends Comparable<K>, V> {

    private static final class Node<K, V> {
        K key;
        V value;
        boolean red;
        Node<K, V> left;
        Node<K, V> right;
        Node<K, V> parent;
    }

    private final Node<K, V> nil = new Node<>();
    private Node<K, V> root;
    private int size;

    public RedBlackTree() {
        nil.red = false;
        nil.left = nil;
        nil.right = nil;
        nil.parent = nil;
        root = nil;
    }

    public int size() {
        return size;
    }

    public boolean isEmpty() {
        return size == 0;
    }

    /** Inserts the key, or replaces its value if present. Returns true if a new key was added. */
    public boolean put(K key, V value) {
        Node<K, V> y = nil;
        Node<K, V> x = root;
        while (x != nil) {
            y = x;
            int c = key.compareTo(x.key);
            if (c == 0) {
                x.value = value;
                return false;
            }
            x = c < 0 ? x.left : x.right;
        }
        Node<K, V> z = new Node<>();
        z.key = key;
        z.value = value;
        z.red = true;
        z.left = nil;
        z.right = nil;
        z.parent = y;
        if (y == nil) {
            root = z;
        } else if (key.compareTo(y.key) < 0) {
            y.left = z;
        } else {
            y.right = z;
        }
        size++;
        insertFixup(z);
        return true;
    }

    /** Returns the value for the key, or null if absent. */
    public V get(K key) {
        Node<K, V> n = findNode(key);
        return n == nil ? null : n.value;
    }

    public boolean containsKey(K key) {
        return findNode(key) != nil;
    }

    /** Removes the key. Returns false if it was not present. */
    public boolean remove(K key) {
        Node<K, V> z = findNode(key);
        if (z == nil) {
            return false;
        }
        Node<K, V> y = z;
        boolean yOriginalRed = y.red;
        Node<K, V> x;
        if (z.left == nil) {
            x = z.right;
            transplant(z, z.right);
        } else if (z.right == nil) {
            x = z.left;
            transplant(z, z.left);
        } else {
            y = minimum(z.right);
            yOriginalRed = y.red;
            x = y.right;
            if (y.parent == z) {
                x.parent = y;
            } else {
                transplant(y, y.right);
                y.right = z.right;
                y.right.parent = y;
            }
            transplant(z, y);
            y.left = z.left;
            y.left.parent = y;
            y.red = z.red;
        }
        if (!yOriginalRed) {
            deleteFixup(x);
        }
        size--;
        nil.parent = nil;
        nil.red = false;
        return true;
    }

    public K firstKey() {
        return root == nil ? null : minimum(root).key;
    }

    public K lastKey() {
        return root == nil ? null : maximum(root).key;
    }

    public V firstValue() {
        return root == nil ? null : minimum(root).value;
    }

    public V lastValue() {
        return root == nil ? null : maximum(root).value;
    }

    /** Up to {@code limit} values, from the largest key downwards. */
    public List<V> descendingValues(int limit) {
        List<V> out = new ArrayList<>();
        descending(root, limit, out);
        return out;
    }

    public List<K> ascendingKeys() {
        List<K> out = new ArrayList<>();
        ascending(root, out);
        return out;
    }

    public int height() {
        return height(root);
    }

    /** Checks BST order, root black, no red-red parent/child, and equal black height on all paths. */
    public boolean validate() {
        if (root == nil) {
            return true;
        }
        if (root.red) {
            return false;
        }
        return check(root, null, null) >= 0;
    }

    // ---------------------------------------------------------------- internals

    private Node<K, V> findNode(K key) {
        Node<K, V> x = root;
        while (x != nil) {
            int c = key.compareTo(x.key);
            if (c == 0) {
                return x;
            }
            x = c < 0 ? x.left : x.right;
        }
        return nil;
    }

    private Node<K, V> minimum(Node<K, V> x) {
        while (x.left != nil) {
            x = x.left;
        }
        return x;
    }

    private Node<K, V> maximum(Node<K, V> x) {
        while (x.right != nil) {
            x = x.right;
        }
        return x;
    }

    private void rotateLeft(Node<K, V> x) {
        Node<K, V> y = x.right;
        x.right = y.left;
        if (y.left != nil) {
            y.left.parent = x;
        }
        y.parent = x.parent;
        if (x.parent == nil) {
            root = y;
        } else if (x == x.parent.left) {
            x.parent.left = y;
        } else {
            x.parent.right = y;
        }
        y.left = x;
        x.parent = y;
    }

    private void rotateRight(Node<K, V> y) {
        Node<K, V> x = y.left;
        y.left = x.right;
        if (x.right != nil) {
            x.right.parent = y;
        }
        x.parent = y.parent;
        if (y.parent == nil) {
            root = x;
        } else if (y == y.parent.right) {
            y.parent.right = x;
        } else {
            y.parent.left = x;
        }
        x.right = y;
        y.parent = x;
    }

    private void insertFixup(Node<K, V> z) {
        while (z.parent.red) {
            if (z.parent == z.parent.parent.left) {
                Node<K, V> uncle = z.parent.parent.right;
                if (uncle.red) {
                    z.parent.red = false;
                    uncle.red = false;
                    z.parent.parent.red = true;
                    z = z.parent.parent;
                } else {
                    if (z == z.parent.right) {
                        z = z.parent;
                        rotateLeft(z);
                    }
                    z.parent.red = false;
                    z.parent.parent.red = true;
                    rotateRight(z.parent.parent);
                }
            } else {
                Node<K, V> uncle = z.parent.parent.left;
                if (uncle.red) {
                    z.parent.red = false;
                    uncle.red = false;
                    z.parent.parent.red = true;
                    z = z.parent.parent;
                } else {
                    if (z == z.parent.left) {
                        z = z.parent;
                        rotateRight(z);
                    }
                    z.parent.red = false;
                    z.parent.parent.red = true;
                    rotateLeft(z.parent.parent);
                }
            }
        }
        root.red = false;
    }

    private void transplant(Node<K, V> u, Node<K, V> v) {
        if (u.parent == nil) {
            root = v;
        } else if (u == u.parent.left) {
            u.parent.left = v;
        } else {
            u.parent.right = v;
        }
        v.parent = u.parent;
    }

    private void deleteFixup(Node<K, V> x) {
        while (x != root && !x.red) {
            if (x == x.parent.left) {
                Node<K, V> w = x.parent.right;
                if (w.red) {
                    w.red = false;
                    x.parent.red = true;
                    rotateLeft(x.parent);
                    w = x.parent.right;
                }
                if (!w.left.red && !w.right.red) {
                    w.red = true;
                    x = x.parent;
                } else {
                    if (!w.right.red) {
                        w.left.red = false;
                        w.red = true;
                        rotateRight(w);
                        w = x.parent.right;
                    }
                    w.red = x.parent.red;
                    x.parent.red = false;
                    w.right.red = false;
                    rotateLeft(x.parent);
                    x = root;
                }
            } else {
                Node<K, V> w = x.parent.left;
                if (w.red) {
                    w.red = false;
                    x.parent.red = true;
                    rotateRight(x.parent);
                    w = x.parent.left;
                }
                if (!w.left.red && !w.right.red) {
                    w.red = true;
                    x = x.parent;
                } else {
                    if (!w.left.red) {
                        w.right.red = false;
                        w.red = true;
                        rotateLeft(w);
                        w = x.parent.left;
                    }
                    w.red = x.parent.red;
                    x.parent.red = false;
                    w.left.red = false;
                    rotateRight(x.parent);
                    x = root;
                }
            }
        }
        x.red = false;
    }

    private void descending(Node<K, V> n, int limit, List<V> out) {
        if (n == nil || out.size() >= limit) {
            return;
        }
        descending(n.right, limit, out);
        if (out.size() < limit) {
            out.add(n.value);
        }
        descending(n.left, limit, out);
    }

    private void ascending(Node<K, V> n, List<K> out) {
        if (n == nil) {
            return;
        }
        ascending(n.left, out);
        out.add(n.key);
        ascending(n.right, out);
    }

    private int height(Node<K, V> n) {
        return n == nil ? 0 : 1 + Math.max(height(n.left), height(n.right));
    }

    /** Returns the black height of the subtree, or -1 if an invariant is violated. */
    private int check(Node<K, V> n, K lo, K hi) {
        if (n == nil) {
            return 1;
        }
        if (lo != null && n.key.compareTo(lo) <= 0) {
            return -1;
        }
        if (hi != null && n.key.compareTo(hi) >= 0) {
            return -1;
        }
        if (n.red && (n.left.red || n.right.red)) {
            return -1;
        }
        int l = check(n.left, lo, n.key);
        int r = check(n.right, n.key, hi);
        if (l < 0 || r < 0 || l != r) {
            return -1;
        }
        return l + (n.red ? 0 : 1);
    }
}
