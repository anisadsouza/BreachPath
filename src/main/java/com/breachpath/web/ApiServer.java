package com.breachpath.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HTTP layer: routes REST requests to {@link BreachPathService}, serves the static frontend from the
 * classpath, and turns every failure into a JSON error with a suitable status code.
 *
 * <p>Built on the JDK's own {@code com.sun.net.httpserver}, so the backend needs no framework
 * dependency. All algorithms run in the service on the server; the frontend only displays results.
 *
 * <p>Status codes: 200 success, 400 invalid input, 404 unknown route, 405 wrong method, 409 no analysis
 * yet or benchmark busy, 413 body over {@link #MAX_BODY} bytes, 415 body not JSON, 500 unexpected error.
 */
public final class ApiServer {
    /** Largest accepted request body (an upload of all five data files must fit). */
    public static final int MAX_BODY = 2 * 1024 * 1024;

    private static final String CSP = "default-src 'self'; script-src 'self'; style-src 'self'; "
            + "font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

    /** Static files the server will deliver: public path to {classpath resource, content type}. */
    private static final Map<String, String[]> STATIC = Map.of(
            "/", new String[]{"/web/index.html", "text/html; charset=utf-8"},
            "/index.html", new String[]{"/web/index.html", "text/html; charset=utf-8"},
            "/app.js", new String[]{"/web/app.js", "text/javascript; charset=utf-8"},
            "/style.css", new String[]{"/web/style.css", "text/css; charset=utf-8"},
            "/fonts/FiraSans-Regular.ttf", new String[]{"/fonts/FiraSans-Regular.ttf", "font/ttf"},
            "/fonts/FiraSans-Bold.ttf", new String[]{"/fonts/FiraSans-Bold.ttf", "font/ttf"},
            "/fonts/IBMPlexMono-Regular.ttf", new String[]{"/fonts/IBMPlexMono-Regular.ttf", "font/ttf"});

    private final BreachPathService service;
    private final HttpServer server;
    private final ExecutorService pool = Executors.newFixedThreadPool(4, r -> {
        Thread t = new Thread(r, "breachpath-http");
        t.setDaemon(true);
        return t;
    });

    /** @param port 0 picks a free port (used by tests) */
    public ApiServer(BreachPathService service, String host, int port) throws IOException {
        this.service = service;
        this.server = HttpServer.create(new InetSocketAddress(host, port), 0);
        this.server.createContext("/", this::handle);
        this.server.setExecutor(pool);
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
        pool.shutdownNow();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    // ---- request handling -------------------------------------------------------------------

    private void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            if (path.startsWith("/api/")) {
                route(ex, method, path);
            } else {
                serveStatic(ex, method, path);
            }
        } catch (HttpError e) {
            sendJson(ex, e.status, error(e.getMessage(), e.status));
        } catch (IllegalArgumentException e) { // includes Json.ParseException
            sendJson(ex, 400, error(e.getMessage(), 400));
        } catch (IllegalStateException e) {
            sendJson(ex, 409, error(e.getMessage(), 409));
        } catch (Exception e) {
            System.err.println("Unexpected error for " + ex.getRequestMethod() + " " + ex.getRequestURI() + ": " + e);
            sendJson(ex, 500, error("Internal error; see the server log", 500));
        } finally {
            ex.close();
        }
    }

    private void route(HttpExchange ex, String method, String path) throws IOException {
        Map<String, String> q = query(ex.getRequestURI().getRawQuery());
        switch (path) {
            case "/api/health" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.health());
            }
            case "/api/topology" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.topology());
            }
            case "/api/analyse" -> {
                allow(method, "POST");
                sendJson(ex, 200, service.analyse(body(ex)));
            }
            case "/api/result" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.result());
            }
            case "/api/incidents" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.incidents());
            }
            case "/api/incidents/evidence" -> {
                allow(method, "POST");
                sendJson(ex, 200, service.addEvidence(body(ex)));
            }
            case "/api/incidents/close" -> {
                allow(method, "POST");
                sendJson(ex, 200, service.closeIncident(body(ex)));
            }
            case "/api/ioc/search" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.iocSearch(q.getOrDefault("prefix", "")));
            }
            case "/api/ioc/screen" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.iocScreen(q.get("indicator")));
            }
            case "/api/patterns" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.patterns(q.get("pattern")));
            }
            case "/api/whatif" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.whatIf());
            }
            case "/api/links/reset" -> {
                allow(method, "POST");
                requireJson(ex);
                sendJson(ex, 200, service.resetLinkCosts());
            }
            case "/api/data" -> {
                allow(method, "POST");
                sendJson(ex, 200, service.replaceData(body(ex)));
            }
            case "/api/data/reset" -> {
                allow(method, "POST");
                requireJson(ex);
                sendJson(ex, 200, service.resetData());
            }
            case "/api/benchmarks" -> {
                allow(method, "GET");
                sendJson(ex, 200, service.benchmarks(q.get("profile")));
            }
            case "/api/benchmarks/last" -> {
                allow(method, "GET");
                Map<String, Object> last = service.lastBenchmark();
                if (last == null) {
                    throw new HttpError(404, "No benchmark has been run yet");
                }
                sendJson(ex, 200, last);
            }
            case "/api/report" -> {
                allow(method, "GET");
                byte[] html = service.reportHtml().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"breachpath-report.html\"");
                send(ex, 200, "text/html; charset=utf-8", html);
            }
            default -> {
                if (path.startsWith("/api/links/")) {
                    allow(method, "PUT");
                    int index;
                    try {
                        index = Integer.parseInt(path.substring("/api/links/".length()));
                    } catch (NumberFormatException e) {
                        throw new HttpError(404, "No such link: " + path.substring("/api/links/".length()));
                    }
                    sendJson(ex, 200, service.setLinkCost(index, body(ex)));
                } else {
                    throw new HttpError(404, "Unknown endpoint: " + path);
                }
            }
        }
    }

    private void serveStatic(HttpExchange ex, String method, String path) throws IOException {
        allow(method, "GET");
        String[] entry = STATIC.get(path);
        if (entry == null) {
            throw new HttpError(404, "Not found: " + path);
        }
        try (InputStream in = ApiServer.class.getResourceAsStream(entry[0])) {
            if (in == null) {
                throw new HttpError(404, "Not found: " + path);
            }
            byte[] data = in.readAllBytes();
            ex.getResponseHeaders().set("Content-Security-Policy", CSP);
            send(ex, 200, entry[1], data);
        }
    }

    // ---- helpers ----------------------------------------------------------------------------

    private static void allow(String actual, String expected) {
        if (!actual.equals(expected)) {
            throw new HttpError(405, "Use " + expected + " for this endpoint");
        }
    }

    /**
     * Non-GET requests must declare a JSON body. Browsers cannot send that content type from a
     * cross-site form without a CORS preflight (which this server never approves), which blocks
     * cross-site request forgery.
     */
    private static void requireJson(HttpExchange ex) {
        String type = ex.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.toLowerCase().startsWith("application/json")) {
            throw new HttpError(415, "Send the request with Content-Type: application/json");
        }
    }

    private static Map<String, Object> body(HttpExchange ex) throws IOException {
        requireJson(ex);
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) > 0) {
                buf.write(chunk, 0, n);
                if (buf.size() > MAX_BODY) {
                    throw new HttpError(413, "Request body is larger than " + (MAX_BODY / 1024) + " KB");
                }
            }
            return Json.parseObject(buf.toString(StandardCharsets.UTF_8));
        }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }

    private static Map<String, Object> error(String message, int status) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", message);
        m.put("status", status);
        return m;
    }

    private static void sendJson(HttpExchange ex, int status, Object value) throws IOException {
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        send(ex, status, "application/json; charset=utf-8", Json.write(value).getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int status, String type, byte[] data) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(status, data.length == 0 ? -1 : data.length);
        if (data.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(data);
            }
        }
    }

    /** A request failure with the HTTP status to report. */
    private static final class HttpError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        final int status;

        HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }
}