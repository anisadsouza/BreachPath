package com.breachpath.model;

/** A network connection between two assets (indexes into the topology's asset list). */
public record Link(int from, int to, int cost, boolean bidirectional) {
}
