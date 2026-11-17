package com.breachpath.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Starts the BreachPath web application: a Java REST API plus the browser frontend.
 *
 * <p>Usage: {@code java -cp target/classes com.breachpath.web.WebApp [dataDir] [port]}
 *
 * <p>Settings (command line wins over environment): data directory {@code BREACHPATH_DATA}
 * (default {@code data}), port {@code PORT} (default 8080), bind address {@code BREACHPATH_HOST}
 * (default 127.0.0.1, so the tool is reachable only from this computer unless you change it).
 * None of these is a secret.
 */
public final class WebApp {
    private WebApp() {
    }

    public static void main(String[] args) {
        String dir = args.length > 0 ? args[0] : env("BREACHPATH_DATA", "data");
        String portText = args.length > 1 ? args[1] : env("PORT", "8080");
        String host = env("BREACHPATH_HOST", "127.0.0.1");

        int port;
        try {
            port = Integer.parseInt(portText.trim());
            if (port < 0 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            System.err.println("Invalid port '" + portText + "': use a number from 0 to 65535");
            System.exit(2);
            return;
        }
        Path dataDir = Path.of(dir);
        if (!Files.isDirectory(dataDir)) {
            System.err.println("Data directory not found: " + dataDir.toAbsolutePath()
                    + "\nRun from the project folder, or pass the folder as the first argument.");
            System.exit(2);
            return;
        }
        try {
            BreachPathService service = new BreachPathService(dataDir);
            ApiServer server = new ApiServer(service, host, port);
            server.start();
            Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
            System.out.println("BreachPath is running at http://" + (host.equals("0.0.0.0") ? "localhost" : host)
                    + ":" + server.port() + "/  (data: " + dataDir.toAbsolutePath() + ")");
            System.out.println("Press Ctrl+C to stop.");
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("Could not start: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}