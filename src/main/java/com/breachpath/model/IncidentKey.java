package com.breachpath.model;

/**
 * Composite key for the red-black tree: ordered by risk score, then by incident id.
 * For equal scores the OLDER incident (lower id) ranks higher, so ties are always
 * broken the same way.
 */
public record IncidentKey(int riskScore, int incidentId) implements Comparable<IncidentKey> {
    @Override
    public int compareTo(IncidentKey other) {
        int c = Integer.compare(riskScore, other.riskScore);
        return c != 0 ? c : Integer.compare(other.incidentId, incidentId);
    }
}
