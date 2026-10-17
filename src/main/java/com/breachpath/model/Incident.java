package com.breachpath.model;

import java.util.List;

/** An investigated security incident with an explainable risk score. */
public record Incident(int id, String host, int riskScore, List<String> reasons) {
    public IncidentKey key() {
        return new IncidentKey(riskScore, id);
    }
}
