package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.engine.IocEngine;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The Bloom filter only screens: answers must match an exact-only reference, and positives are always confirmed. */
class BloomIocIntegrationTest {

    private static final List<String> FEED = List.of(
            "update-cdn.evil-domain.com", "185.220.101.7", "/tmp/.hidden/payload.sh",
            "login-portal.phish-example.net", "203.0.113.*", "C:\\Users\\Public\\*");

    private static String randomIndicator(Random rnd) {
        StringBuilder sb = new StringBuilder();
        int len = 6 + rnd.nextInt(24);
        for (int i = 0; i < len; i++) {
            sb.append("abcdefghijklmnopqrstuvwxyz0123456789.-/"
                    .charAt(rnd.nextInt(39)));
        }
        return sb.toString();
    }

    @Test
    void answersMatchAnExactOnlyReference() {
        IocEngine engine = IocEngine.fromLines(FEED);
        Set<String> exact = new HashSet<>();
        List<String> prefixes = new ArrayList<>();
        for (String s : FEED) {
            String low = s.toLowerCase(Locale.ROOT);
            if (low.endsWith("*")) {
                prefixes.add(low.substring(0, low.length() - 1));
            } else {
                exact.add(low);
            }
        }
        Random rnd = new Random(8);
        List<String> probes = new ArrayList<>(FEED.subList(0, 4));
        probes.add("203.0.113.55");
        probes.add("c:\\users\\public\\evil.exe");
        for (int i = 0; i < 20_000; i++) {
            probes.add(randomIndicator(rnd));
        }
        for (String p : probes) {
            String low = p.toLowerCase(Locale.ROOT);
            boolean expected = exact.contains(low) || prefixes.stream().anyMatch(low::startsWith);
            assertEquals(expected, engine.isKnownIndicator(p), "indicator " + p);
        }
    }

    @Test
    void aBloomFalsePositiveIsRejectedByTheExactCheck() {
        IocEngine engine = IocEngine.fromLines(List.of("a.example", "b.example", "c.example", "d.example"));
        Random rnd = new Random(12);
        int found = 0;
        for (int i = 0; i < 300_000 && found < 3; i++) {
            String s = randomIndicator(rnd);
            IocEngine.Screening r = engine.screen(s);
            if (r.bloomPossible()) {
                found++;
                assertFalse(r.exactConfirmed());
                assertFalse(r.known(), "a Bloom hit must not be reported as a known indicator");
                assertTrue(r.bloomFalsePositive());
            }
        }
        assertTrue(found > 0, "the tiny filter should produce at least one false positive in 300,000 probes");
        assertTrue(engine.bloomStats().falsePositives() >= found);
    }

    @Test
    void realIndicatorsAreConfirmedAndCleanOnesUsuallySkipTheTrie() {
        IocEngine engine = IocEngine.fromLines(FEED);
        IocEngine.Screening hit = engine.screen("185.220.101.7");
        assertTrue(hit.bloomPossible() && hit.exactConfirmed() && hit.known());
        assertFalse(hit.bloomFalsePositive());
        IocEngine.Screening miss = engine.screen("totally-clean.example.org");
        assertFalse(miss.known());
        assertFalse(engine.isKnownIndicator("another-clean-host.internal"));
    }

    @Test
    void prefixRulesStillMatchWhenTheFilterSaysAbsent() {
        IocEngine engine = IocEngine.fromLines(FEED);
        IocEngine.Screening r = engine.screen("203.0.113.200");
        assertFalse(r.exactConfirmed());
        assertTrue(r.prefixRuleMatch());
        assertTrue(r.known());
    }

    @Test
    void blankAndNullAreNeverKnownAndMatchingIsCaseInsensitive() {
        IocEngine engine = IocEngine.fromLines(FEED);
        assertFalse(engine.isKnownIndicator(null));
        assertFalse(engine.isKnownIndicator(""));
        assertFalse(engine.screen("").known());
        assertTrue(engine.isKnownIndicator("UPDATE-CDN.EVIL-DOMAIN.COM"));
    }

    @Test
    void emptyFeedKnowsNothingAndCountersTrackLookups() {
        IocEngine empty = IocEngine.fromLines(List.of());
        assertFalse(empty.isKnownIndicator("anything"));
        assertEquals(0, empty.size());

        IocEngine engine = IocEngine.fromLines(FEED);
        engine.screen("185.220.101.7");
        engine.screen("clean-1.example");
        engine.screen("clean-2.example");
        IocEngine.BloomStats stats = engine.bloomStats();
        assertEquals(3, stats.lookups());
        assertEquals(stats.lookups(), stats.bloomRejects() + stats.bloomPasses());
        assertEquals(4, stats.items());
        assertTrue(stats.lookupsAvoided() >= 0.0 && stats.lookupsAvoided() <= 1.0);
    }
}