package com.breachpath.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * Explainable risk score, capped at 100:
 * burst (peak hourly alerts x3, max 30) + volume (total alerts / 5, max 20)
 * + IOC hits (20 each, max 30) + pattern hits (15 each, max 20)
 * + 10 if the host can reach a protected target.
 */
public class RiskScorer {

    public RiskAssessment score(String host, int fromHour, int toHour, EventTimeline timeline,
                                int iocHits, int patternHits, boolean reachesProtectedTarget) {
        int total = timeline.total(host, fromHour, toHour);
        int peak = timeline.peak(host, fromHour, toHour);

        int burst = Math.min(30, peak * 3);
        int volume = Math.min(20, total / 5);
        int ioc = Math.min(30, iocHits * 20);
        int pattern = Math.min(20, patternHits * 15);
        int path = reachesProtectedTarget ? 10 : 0;

        List<String> reasons = new ArrayList<>();
        if (burst > 0) {
            reasons.add("peak of " + peak + " alerts in one hour (+" + burst + ")");
        }
        if (volume > 0) {
            reasons.add(total + " alerts in window (+" + volume + ")");
        }
        if (ioc > 0) {
            reasons.add(iocHits + " known IOC hit(s) (+" + ioc + ")");
        }
        if (pattern > 0) {
            reasons.add(patternHits + " suspicious command pattern(s) (+" + pattern + ")");
        }
        if (path > 0) {
            reasons.add("can reach a protected target (+" + path + ")");
        }
        int score = Math.min(100, burst + volume + ioc + pattern + path);
        return new RiskAssessment(score, reasons);
    }
}
