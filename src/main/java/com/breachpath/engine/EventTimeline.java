package com.breachpath.engine;

import com.breachpath.model.SecurityEvent;
import com.breachpath.segmenttree.SegmentTree;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Per-host hourly alert counts, each backed by a segment tree for fast window queries. */
public class EventTimeline {
    private final int hours;
    private final Map<String, SegmentTree> trees = new HashMap<>();

    public EventTimeline(java.util.List<SecurityEvent> events, int minHours) {
        int max = minHours - 1;
        for (SecurityEvent e : events) {
            if (e.hour() < 0) {
                throw new IllegalArgumentException("Negative hour in event for " + e.host());
            }
            max = Math.max(max, e.hour());
        }
        final int h = max + 1;
        this.hours = h;
        Map<String, int[]> raw = new HashMap<>();
        for (SecurityEvent e : events) {
            raw.computeIfAbsent(e.host(), k -> new int[h])[e.hour()] += e.count();
        }
        raw.forEach((host, counts) -> trees.put(host, new SegmentTree(counts)));
    }

    public int hours() {
        return hours;
    }

    public Set<String> hosts() {
        return new TreeSet<>(trees.keySet());
    }

    /** Total alerts for the host in hours [from, to]. */
    public int total(String host, int from, int to) {
        checkWindow(from, to);
        SegmentTree t = trees.get(host);
        return t == null ? 0 : t.rangeSum(from, to);
    }

    /** Highest single-hour alert count for the host in hours [from, to]. */
    public int peak(String host, int from, int to) {
        checkWindow(from, to);
        SegmentTree t = trees.get(host);
        return t == null ? 0 : t.rangeMax(from, to);
    }

    /** Adds new alerts to one hour (a point update on the host's segment tree). */
    public void addAlerts(String host, int hour, int delta) {
        if (hour < 0 || hour >= hours) {
            throw new IllegalArgumentException("Hour out of range: " + hour);
        }
        SegmentTree t = trees.computeIfAbsent(host, k -> new SegmentTree(new int[hours]));
        t.update(hour, t.get(hour) + delta);
    }

    private void checkWindow(int from, int to) {
        if (from < 0 || to >= hours || from > to) {
            throw new IllegalArgumentException("Invalid window [" + from + ", " + to + "], hours = " + hours);
        }
    }
}
