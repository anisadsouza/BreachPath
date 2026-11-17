package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.web.ApiServer;
import com.breachpath.web.BreachPathService;
import com.breachpath.web.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** End-to-end tests of the REST API on a real local server (free port, sample data). */
class ApiServerTest {
    private HttpClient http;
    private String base;

    @BeforeEach
    void setUp() throws Exception {
        http = HttpClient.newHttpClient();
        ApiServer server = new ApiServer(new BreachPathService(Path.of("data")), "127.0.0.1", 0);
        server.start();
        base = "http://127.0.0.1:" + server.port();
        servers.add(server);
    }

    private final java.util.List<ApiServer> servers = new java.util.ArrayList<>();

    private void stop() {
        servers.forEach(ApiServer::stop);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body, String contentType) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postJson(String path, String body) throws Exception {
        return post(path, body, "application/json");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> json(HttpResponse<String> r) {
        return (Map<String, Object>) Json.parseObject(r.body());
    }

    @Test
    void healthReportsTheLoadedDataset() throws Exception {
        try {
            HttpResponse<String> r = get("/api/health");
            assertEquals(200, r.statusCode());
            Map<String, Object> m = json(r);
            assertEquals("ok", m.get("status"));
            assertEquals(12, ((Number) m.get("assets")).intValue());
        } finally {
            stop();
        }
    }

    @Test
    void analyseReturnsPathsRankedIncidentsPlansAndBloomStats() throws Exception {
        try {
            HttpResponse<String> r = postJson("/api/analyse",
                    "{\"compromised\":[\"WS-Alice\"],\"targets\":[\"DB-PROD\"],\"fromHour\":0,\"toHour\":23}");
            assertEquals(200, r.statusCode());
            Map<String, Object> m = json(r);
            List<?> paths = (List<?>) m.get("attackPaths");
            assertFalse(paths.isEmpty());
            List<?> incidents = (List<?>) m.get("incidents");
            int previous = Integer.MAX_VALUE;
            for (Object o : incidents) {
                int score = ((Number) ((Map<?, ?>) o).get("score")).intValue();
                assertTrue(score <= previous, "incidents must be ranked highest first");
                previous = score;
            }
            Map<?, ?> containment = (Map<?, ?>) m.get("containment");
            Map<?, ?> a = (Map<?, ?>) containment.get("A");
            Map<?, ?> b = (Map<?, ?>) containment.get("B");
            assertEquals(Boolean.TRUE, a.get("feasible"));
            assertEquals(Boolean.TRUE, a.get("verified"));
            assertTrue(((Number) b.get("totalCost")).intValue() <= ((Number) a.get("totalCost")).intValue(),
                    "allowing the compromised host to be isolated can only lower the cost");
            assertNotNull(m.get("riskStats"));
            assertNotNull(m.get("bloom"));
        } finally {
            stop();
        }
    }

    @Test
    void invalidAnalysisRequestsGetClearErrors() throws Exception {
        try {
            HttpResponse<String> unknown = postJson("/api/analyse", "{\"compromised\":[\"NOPE\"],\"targets\":[\"DB-PROD\"]}");
            assertEquals(400, unknown.statusCode());
            assertTrue(((String) json(unknown).get("error")).contains("Unknown asset: NOPE"));

            HttpResponse<String> same = postJson("/api/analyse", "{\"compromised\":[\"DB-PROD\"],\"targets\":[\"DB-PROD\"]}");
            assertEquals(400, same.statusCode());

            HttpResponse<String> window = postJson("/api/analyse",
                    "{\"compromised\":[\"WS-Alice\"],\"targets\":[\"DB-PROD\"],\"fromHour\":20,\"toHour\":3}");
            assertEquals(400, window.statusCode());

            HttpResponse<String> garbage = postJson("/api/analyse", "{not json");
            assertEquals(400, garbage.statusCode());

            HttpResponse<String> empty = postJson("/api/analyse", "{\"compromised\":[],\"targets\":[\"DB-PROD\"]}");
            assertEquals(400, empty.statusCode());
        } finally {
            stop();
        }
    }

    @Test
    void routingAndContentTypeRules() throws Exception {
        try {
            assertEquals(404, get("/api/nothing").statusCode());
            assertEquals(405, get("/api/analyse").statusCode());
            assertEquals(415, post("/api/analyse", "{}", "text/plain").statusCode());
            assertEquals(415, post("/api/analyse", "{}", null).statusCode());
            HttpResponse<String> page = get("/");
            assertEquals(200, page.statusCode());
            assertTrue(page.body().contains("BreachPath"));
            assertTrue(page.headers().firstValue("Content-Security-Policy").isPresent());
            assertEquals(404, get("/../pom.xml").statusCode());
        } finally {
            stop();
        }
    }

    @Test
    void indicatorScreeningExplainsTheBloomResult() throws Exception {
        try {
            Map<String, Object> hit = json(get("/api/ioc/screen?indicator=185.220.101.7"));
            assertEquals(Boolean.TRUE, hit.get("bloomPossible"));
            assertEquals(Boolean.TRUE, hit.get("exactConfirmed"));
            assertEquals(Boolean.TRUE, hit.get("known"));
            Map<String, Object> miss = json(get("/api/ioc/screen?indicator=clean.example.org"));
            assertEquals(Boolean.FALSE, miss.get("known"));
            assertEquals("definitely absent", miss.get("bloom"));
            assertEquals(400, get("/api/ioc/screen?indicator=").statusCode());
        } finally {
            stop();
        }
    }

    @Test
    void newEvidenceReRanksAnIncident() throws Exception {
        try {
            postJson("/api/analyse", "{\"compromised\":[\"WS-Alice\"],\"targets\":[\"DB-PROD\"]}");
            HttpResponse<String> r = postJson("/api/incidents/evidence", "{\"host\":\"WS-Bob\",\"hour\":10,\"delta\":40}");
            assertEquals(200, r.statusCode());
            Map<?, ?> updated = (Map<?, ?>) json(r).get("updated");
            assertEquals("WS-Bob", updated.get("host"));
            assertEquals(400, postJson("/api/incidents/evidence", "{\"host\":\"WS-Bob\",\"hour\":99,\"delta\":1}").statusCode());
            assertEquals(400, postJson("/api/incidents/evidence", "{\"host\":\"WS-Bob\",\"hour\":1,\"delta\":0}").statusCode());
        } finally {
            stop();
        }
    }

    @Test
    void uploadReplacesDataOnlyWhenEverythingIsValid() throws Exception {
        try {
            String assets = "name,type,isolationCost\\nX,workstation,3\\nY,server,50\\n";
            String edges = "from,to,cost,bidirectional\\nX,Y,7,true\\n";
            String events = "hour,host,eventType,count,indicator,command\\n2,X,LOGIN,4,-,-\\n";
            HttpResponse<String> ok = postJson("/api/data", "{\"assets\":\"" + assets + "\",\"edges\":\"" + edges
                    + "\",\"events\":\"" + events + "\",\"iocs\":\"bad.example\",\"patterns\":\"\"}");
            assertEquals(200, ok.statusCode());
            assertEquals(2, ((Number) json(ok).get("assets")).intValue());
            // The default hosts are not in this network, so there is no analysis until the user picks hosts.
            assertEquals(409, get("/api/result").statusCode());
            HttpResponse<String> run = postJson("/api/analyse", "{\"compromised\":[\"X\"],\"targets\":[\"Y\"]}");
            assertEquals(200, run.statusCode());

            String badAssets = "name,type,isolationCost\\nX,workstation,oops\\n";
            HttpResponse<String> bad = postJson("/api/data", "{\"assets\":\"" + badAssets + "\",\"edges\":\"" + edges
                    + "\",\"events\":\"" + events + "\"}");
            assertEquals(400, bad.statusCode());
            assertTrue(((String) json(bad).get("error")).contains("line 2"));
            assertEquals(2, ((Number) json(get("/api/health")).get("assets")).intValue(), "old data must be kept");
            assertEquals(400, postJson("/api/data", "{\"assets\":\"name,type,isolationCost\\n\"}").statusCode());
        } finally {
            stop();
        }
    }

    @Test
    void oversizedBodiesAreRejected() throws Exception {
        try {
            String big = "{\"assets\":\"" + "a".repeat(ApiServer.MAX_BODY + 10) + "\"}";
            assertEquals(413, postJson("/api/data", big).statusCode());
        } finally {
            stop();
        }
    }
}