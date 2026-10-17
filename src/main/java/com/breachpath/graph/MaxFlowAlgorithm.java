package com.breachpath.graph;

/** A maximum-flow algorithm that also reports the minimum cut. */
public interface MaxFlowAlgorithm {
    String name();

    MaxFlowResult compute(FlowNetwork network, int source, int sink);
}
