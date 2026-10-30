package com.breachpath.ui;

import com.breachpath.engine.ContainmentPlan;
import com.breachpath.model.Incident;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Writes the current analysis as one self-contained HTML page: the incident ranking, both
 * containment scenarios and the what-if sweep. No JavaFX here, so it is unit-tested.
 */
public final class ReportWriter {
    private ReportWriter() {
    }

    public static void write(Path file, DashboardModel model, String generatedAt) throws IOException {
        Files.writeString(file, html(model, generatedAt), StandardCharsets.UTF_8);
    }

    /** The report as an HTML string. {@code generatedAt} is printed as given (it is not read from the clock). */
    public static String html(DashboardModel model, String generatedAt) {
        StringBuilder h = new StringBuilder();
        h.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<title>BreachPath report</title>\n<style>\n")
                .append("body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#20242a;")
                .append("max-width:960px;margin:32px auto;padding:0 20px;line-height:1.45}\n")
                .append("h1{margin-bottom:2px}h2{margin-top:34px;border-bottom:1px solid #cfd5dc;padding-bottom:4px}\n")
                .append("table{border-collapse:collapse;width:100%;margin:10px 0}\n")
                .append("th,td{border:1px solid #cfd5dc;padding:6px 10px;text-align:left;vertical-align:top}\n")
                .append("th{background:#eef1f4}.nowrap{white-space:nowrap}.muted{color:#5d6671}.bad{color:#a3202a}.ok{color:#2a6f4e}\n")
                .append("</style>\n</head>\n<body>\n");

        h.append("<h1>BreachPath report</h1>\n<p class=\"muted\">Generated ").append(esc(generatedAt))
                .append(". All data is synthetic.</p>\n");

        h.append("<h2>Analysis</h2>\n<table>\n");
        row(h, "Compromised hosts", names(model, model.sources()));
        row(h, "Protected targets", names(model, model.targets()));
        row(h, "Alert window", "hours " + model.from() + " to " + model.to());
        h.append("</table>\n");

        List<String> changes = model.costChanges();
        if (!changes.isEmpty()) {
            h.append("<p><strong>Link costs changed from the data file:</strong></p>\n<ul>\n");
            for (String c : changes) {
                h.append("<li>").append(esc(c)).append("</li>\n");
            }
            h.append("</ul>\n");
        }

        h.append("<h2>Incidents, highest risk first</h2>\n");
        List<Incident> ranked = model.ranked();
        if (ranked.isEmpty()) {
            h.append("<p class=\"muted\">No open incidents.</p>\n");
        } else {
            h.append("<table>\n<tr><th>Rank</th><th>Host</th><th>Risk</th><th>Priority</th><th>Why</th></tr>\n");
            int rank = 1;
            for (Incident i : ranked) {
                h.append("<tr><td>").append(rank++).append("</td><td class=\"nowrap\">").append(esc(i.host())).append("</td><td>")
                        .append(i.riskScore()).append("</td><td>").append(DashboardModel.priority(i.riskScore()))
                        .append("</td><td>").append(esc(String.join("; ", i.reasons()))).append("</td></tr>\n");
            }
            h.append("</table>\n");
        }

        h.append("<h2>Containment</h2>\n");
        scenario(h, "Scenario A: compromised hosts stay online", model.plan(DashboardModel.Scenario.STRICT));
        scenario(h, "Scenario B: the compromised host itself may be isolated",
                model.plan(DashboardModel.Scenario.RELAXED));

        h.append("<h2>What if one host were compromised?</h2>\n")
                .append("<p class=\"muted\">Each host is treated as the only compromised one. Internet-facing unpatched ")
                .append("hosts come first, then those that cost most to contain.</p>\n")
                .append("<table>\n<tr><th>Host</th><th>Exposure</th><th>Steps to target</th>")
                .append("<th>Cost to contain, A</th><th>Cost to contain, B</th></tr>\n");
        for (DashboardModel.WhatIfRow r : model.whatIf()) {
            h.append("<tr><td class=\"nowrap\">").append(esc(r.host())).append("</td><td>")
                    .append(r.internetFacing() ? "internet-facing" : "internal")
                    .append(r.patched() ? ", patched" : ", unpatched").append("</td><td>")
                    .append(r.reaches() ? String.valueOf(r.hops()) : "cannot reach").append("</td><td>")
                    .append(cost(r, false)).append("</td><td>").append(cost(r, true)).append("</td></tr>\n");
        }
        h.append("</table>\n");

        h.append("<p class=\"muted\">These results are experiments on synthetic data, not proof of real-world ")
                .append("protection.</p>\n</body>\n</html>\n");
        return h.toString();
    }

    private static void scenario(StringBuilder h, String title, ContainmentPlan plan) {
        h.append("<h3>").append(esc(title)).append("</h3>\n");
        if (!plan.feasible()) {
            h.append("<p class=\"bad\">No finite-cost containment exists: an uncuttable path reaches a target.</p>\n");
            return;
        }
        h.append("<p><strong>Total cost: ").append(plan.totalCost()).append("</strong></p>\n");
        if (plan.actions().isEmpty()) {
            h.append("<p class=\"muted\">No action is needed: no compromised host can reach a target.</p>\n");
        } else {
            h.append("<table>\n<tr><th>Action</th><th>Cost</th></tr>\n");
            for (ContainmentPlan.Action a : plan.actions()) {
                h.append("<tr><td>").append(esc(a.description())).append("</td><td>").append(a.cost())
                        .append("</td></tr>\n");
            }
            h.append("</table>\n");
        }
        h.append("<p>Affected assets: ").append(esc(String.join(", ", plan.affectedAssets()))).append("</p>\n")
                .append(plan.verified()
                        ? "<p class=\"ok\">Verified: no protected target can be reached after the cut.</p>\n"
                        : "<p class=\"bad\">Check failed: a protected target can still be reached.</p>\n");
    }

    private static String cost(DashboardModel.WhatIfRow r, boolean isolationAllowed) {
        if (!r.reaches()) {
            return "none needed";
        }
        boolean feasible = isolationAllowed ? r.feasibleB() : r.feasibleA();
        return feasible ? String.valueOf(isolationAllowed ? r.costB() : r.costA()) : "cannot be cut";
    }

    private static String names(DashboardModel model, List<Integer> indexes) {
        StringBuilder sb = new StringBuilder();
        for (int i : indexes) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(model.topology().asset(i).name());
        }
        return sb.toString();
    }

    private static void row(StringBuilder h, String label, String value) {
        h.append("<tr><th>").append(esc(label)).append("</th><td>").append(esc(value)).append("</td></tr>\n");
    }

    private static String esc(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#39;");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}