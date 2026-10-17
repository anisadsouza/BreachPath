package com.breachpath.engine;

import com.breachpath.model.SecurityEvent;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Distinct IOC hits and pattern-matching commands observed on one host. */
public record HostEvidence(String host, Set<String> iocs, Set<String> commands) {

    public static HostEvidence empty(String host) {
        return new HostEvidence(host, new TreeSet<>(), new TreeSet<>());
    }

    /** Scans the log once and gathers evidence per host. */
    public static Map<String, HostEvidence> collect(List<SecurityEvent> events, IocEngine iocEngine,
                                                    Set<String> matchedCommands) {
        Map<String, HostEvidence> out = new HashMap<>();
        for (SecurityEvent e : events) {
            HostEvidence ev = out.computeIfAbsent(e.host(), HostEvidence::empty);
            if (iocEngine.isKnownIndicator(e.indicator())) {
                ev.iocs().add(e.indicator());
            }
            if (!e.command().isEmpty() && matchedCommands.contains(e.command().toLowerCase(Locale.ROOT))) {
                ev.commands().add(e.command());
            }
        }
        return out;
    }
}
