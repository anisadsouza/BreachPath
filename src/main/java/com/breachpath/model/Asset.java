package com.breachpath.model;

/** A host, server or other asset in the simulated enterprise network. */
public record Asset(String name, String type, int isolationCost) {
}
