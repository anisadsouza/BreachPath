package com.breachpath.model;

/**
 * One aggregated row of the synthetic audit log.
 * {@code count} is the number of alerts; indicator and command are "" when absent.
 */
public record SecurityEvent(int hour, String host, String eventType, int count,
                            String indicator, String command) {
}
