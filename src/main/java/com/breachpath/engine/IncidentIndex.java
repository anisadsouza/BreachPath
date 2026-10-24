package com.breachpath.engine;

import com.breachpath.model.Incident;
import com.breachpath.rbtree.RedBlackTree;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ordered incident index. The red-black tree is keyed by (riskScore, incidentId); a side map finds
 * an incident's current key by id so scores can be updated by remove + re-insert.
 */
public class IncidentIndex {
    private final RedBlackTree<com.breachpath.model.IncidentKey, Incident> tree = new RedBlackTree<>();
    private final Map<Integer, Incident> byId = new HashMap<>();
    private int nextId = 1;

    public Incident open(String host, int riskScore, List<String> reasons) {
        Incident incident = new Incident(nextId++, host, riskScore, List.copyOf(reasons));
        tree.put(incident.key(), incident);
        byId.put(incident.id(), incident);
        return incident;
    }

    /** Changes an incident's score (and optionally adds a reason). Returns false if the id is unknown. */
    public boolean updateScore(int id, int newScore, String newReason) {
        Incident old = byId.get(id);
        if (old == null) {
            return false;
        }
        tree.remove(old.key());
        List<String> reasons = new ArrayList<>(old.reasons());
        if (newReason != null) {
            reasons.add(newReason);
        }
        Incident updated = new Incident(id, old.host(), newScore, List.copyOf(reasons));
        tree.put(updated.key(), updated);
        byId.put(id, updated);
        return true;
    }

    /** Closes (removes) an incident. Returns false if the id is unknown. */
    public boolean close(int id) {
        Incident old = byId.remove(id);
        if (old == null) {
            return false;
        }
        tree.remove(old.key());
        return true;
    }

    public Incident find(int id) {
        return byId.get(id);
    }

    /** The k highest-risk incidents, highest first. */
    public List<Incident> top(int k) {
        return tree.descendingValues(k);
    }

    public int size() {
        return tree.size();
    }

    /** A read-only snapshot of the red-black tree, for display. */
    public List<RedBlackTree.NodeView<com.breachpath.model.IncidentKey, Incident>> treeView() {
        return tree.inOrderView();
    }

    public boolean isBalanced() {
        return tree.validate();
    }
}