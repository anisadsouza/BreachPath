package com.breachpath.model;

/**
 * A host, server or other asset in the simulated enterprise network.
 *
 * @param internetFacing true if the asset can be reached from the internet
 * @param patched        true if the asset runs fully patched software
 */
public record Asset(String name, String type, int isolationCost, boolean internetFacing, boolean patched) {

    /** An internal, fully patched asset (the default when the data file has no exposure columns). */
    public Asset(String name, String type, int isolationCost) {
        this(name, type, isolationCost, false, true);
    }

    /** The combination that makes a host an attractive first target. */
    public boolean exposedAndUnpatched() {
        return internetFacing && !patched;
    }
}