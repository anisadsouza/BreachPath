package com.breachpath.engine;

import java.util.List;
import java.util.Set;

/**
 * A recommended containment: which hosts to isolate and which links to block.
 *
 * @param feasible false if no finite-cost cut exists
 * @param verified true if, after applying the actions, no target is reachable from any compromised host
 */
public record ContainmentPlan(String algorithm, boolean feasible, int totalCost, List<Action> actions,
                              Set<String> affectedAssets, boolean verified, long nanos) {

    /** One containment action. type is ISOLATE_HOST or BLOCK_LINK. */
    public record Action(String type, String description, int cost) {
    }
}
