package com.breachpath.engine;

import java.util.List;

/** A risk score (0-100) together with the reasons that produced it. */
public record RiskAssessment(int score, List<String> reasons) {
}
