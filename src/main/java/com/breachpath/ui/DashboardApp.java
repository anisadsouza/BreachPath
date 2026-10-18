package com.breachpath.ui;

import com.breachpath.engine.Benchmarks;
import com.breachpath.engine.ContainmentPlan;
import com.breachpath.model.Incident;
import com.breachpath.model.Link;
import com.breachpath.model.Topology;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Spinner;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JavaFX dashboard with four tabs: Overview, Investigation, Containment and Benchmarks.
 * Run with: mvn javafx:run
 */
public final class DashboardApp extends Application {
    private static final double NODE_R = 24;
    private static final String RED = "#c62828";
    private static final String ORANGE = "#ef6c00";
    private static final String YELLOW = "#fbc02d";
    private static final String GREEN = "#2e7d32";
    private static final String BLUE = "#0d47a1";
    private static final String GREY = "#546e7a";

    private DashboardModel model;
    private String selectedHost;
    private boolean updatingSelection;

    // top bar
    private final TextField compromisedField = new TextField("WS-Alice");
    private final TextField targetField = new TextField("DB-PROD");
    private final Spinner<Integer> fromSpinner = new Spinner<>(0, 23, 0);
    private final Spinner<Integer> toSpinner = new Spinner<>(0, 23, 23);
    private final Label status = new Label();

    // overview
    private final GraphView overviewGraph = new GraphView(false);
    private final VBox cardsBox = new VBox(8);
    private final Label selectionSummary = new Label();
    private final CategoryAxis hourAxis = new CategoryAxis();
    private final NumberAxis countAxis = new NumberAxis();
    private final BarChart<String, Number> chart = new BarChart<>(hourAxis, countAxis);

    // investigation
    private final TableView<Incident> table = new TableView<>();
    private final TextArea reasonsArea = new TextArea();
    private final TextArea patternsArea = new TextArea();
    private final TextField iocField = new TextField();
    private final ListView<String> iocResults = new ListView<>();
    private final Spinner<Integer> hourSpinner = new Spinner<>(0, 23, 12);
    private final Spinner<Integer> deltaSpinner = new Spinner<>(1, 500, 30);

    // containment
    private final GraphView containmentGraph = new GraphView(true);
    private final ToggleButton scenarioA = new ToggleButton();
    private final ToggleButton scenarioB = new ToggleButton();
    private final VBox planBox = new VBox(8);

    // benchmarks
    private final TextArea benchArea = new TextArea();
    private final Label validationLabel = new Label();
    private final Button benchButton = new Button("Run benchmarks");
    private final ProgressIndicator benchProgress = new ProgressIndicator();

    @Override
    public void start(Stage stage) {
        String dir = getParameters().getNamed().getOrDefault("data", "data");
        try {
            model = DashboardModel.load(Path.of(dir));
        } catch (IOException | RuntimeException e) {
            new Alert(Alert.AlertType.ERROR, "Could not load data from '" + dir + "': " + e.getMessage()).showAndWait();
            Platform.exit();
            return;
        }

        TabPane tabs = new TabPane(
                tab("Overview", buildOverview()),
                tab("Investigation", buildInvestigation()),
                tab("Containment", buildContainment()),
                tab("Benchmarks", buildBenchmarks()));
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        BorderPane root = new BorderPane();
        root.setTop(buildTopBar());
        root.setCenter(tabs);

        stage.setTitle("BreachPath - Enterprise Breach Analysis & Containment");
        stage.setScene(new Scene(root, 1280, 820));
        stage.show();
        runAnalysis();
    }

    private static Tab tab(String title, javafx.scene.Node content) {
        Tab t = new Tab(title, content);
        t.setClosable(false);
        return t;
    }

    // ---- top bar ----------------------------------------------------------------------------

    private VBox buildTopBar() {
        Label title = new Label("BreachPath");
        title.setFont(Font.font(null, FontWeight.BOLD, 20));
        Label subtitle = new Label("Enterprise Breach Analysis & Containment");
        subtitle.setTextFill(Color.web(GREY));
        HBox titles = new HBox(12, title, subtitle);
        titles.setAlignment(Pos.BASELINE_LEFT);

        fromSpinner.setEditable(true);
        toSpinner.setEditable(true);
        fromSpinner.setPrefWidth(72);
        toSpinner.setPrefWidth(72);
        compromisedField.setPrefWidth(180);
        compromisedField.setPromptText("WS-Alice,WS-Bob");
        targetField.setPrefWidth(180);
        targetField.setPromptText("DB-PROD,CLOUD-ADMIN");
        Button run = new Button("Analyse");
        run.setDefaultButton(true);
        run.setStyle("-fx-base: #1565c0; -fx-text-fill: white; -fx-font-weight: bold;");
        run.setOnAction(e -> runAnalysis());
        status.setWrapText(true);
        HBox.setHgrow(status, Priority.ALWAYS);

        HBox controls = new HBox(8, new Label("Compromised host"), compromisedField, new Label("Protected target"),
                targetField, new Label("Hours"), fromSpinner, new Label("to"), toSpinner, run, status);
        controls.setAlignment(Pos.CENTER_LEFT);

        VBox box = new VBox(8, titles, controls);
        box.setPadding(new Insets(10, 14, 8, 14));
        return box;
    }

    // ---- tab 1: overview --------------------------------------------------------------------

    private BorderPane buildOverview() {
        chart.setAnimated(false);
        chart.setLegendVisible(false);
        chart.setCategoryGap(2);
        hourAxis.setLabel("hour of day");
        countAxis.setLabel("alerts");
        chart.setPrefHeight(215);

        selectionSummary.setFont(Font.font(null, FontWeight.BOLD, 13));
        selectionSummary.setWrapText(true);

        Label cardsTitle = sectionTitle("Highest-risk incidents");
        Label hint = new Label("Click a card or a host on the map to see its alert activity.");
        hint.setWrapText(true);
        hint.setMinHeight(Region.USE_PREF_SIZE);
        hint.setTextFill(Color.web(GREY));
        VBox right = new VBox(10, cardsTitle, cardsBox, hint, selectionSummary);
        right.setPadding(new Insets(12));
        right.setPrefWidth(340);

        Label mapTitle = sectionTitle("Network attack path");
        VBox left = new VBox(6, mapTitle, overviewGraph.holder, legend(false));
        left.setPadding(new Insets(12, 0, 6, 12));
        VBox.setVgrow(overviewGraph.holder, Priority.ALWAYS);

        VBox bottom = new VBox(chart);
        bottom.setPadding(new Insets(0, 12, 8, 12));

        BorderPane pane = new BorderPane();
        pane.setCenter(left);
        pane.setRight(right);
        pane.setBottom(bottom);
        return pane;
    }

    // ---- tab 2: investigation ---------------------------------------------------------------

    private TwoColumns buildInvestigation() {
        TableColumn<Incident, Integer> idCol = new TableColumn<>("Id");
        idCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().id()));
        idCol.setMinWidth(45);
        idCol.setMaxWidth(60);
        TableColumn<Incident, String> hostCol = new TableColumn<>("Host");
        hostCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().host()));
        hostCol.setMinWidth(100);
        TableColumn<Incident, Integer> riskCol = new TableColumn<>("Risk");
        riskCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().riskScore()));
        riskCol.setMinWidth(55);
        riskCol.setMaxWidth(75);
        TableColumn<Incident, String> levelCol = new TableColumn<>("Priority");
        levelCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(level(c.getValue().riskScore())));
        levelCol.setMinWidth(80);
        levelCol.setMaxWidth(100);
        TableColumn<Incident, String> whyCol = new TableColumn<>("Top reason");
        whyCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(
                c.getValue().reasons().isEmpty() ? "" : c.getValue().reasons().get(0)));
        whyCol.setPrefWidth(260);
        table.getColumns().add(idCol);
        table.getColumns().add(hostCol);
        table.getColumns().add(riskCol);
        table.getColumns().add(levelCol);
        table.getColumns().add(whyCol);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.getSelectionModel().selectedItemProperty().addListener((o, a, b) -> {
            if (!updatingSelection && b != null) {
                selectHost(b.host());
            }
        });

        reasonsArea.setEditable(false);
        reasonsArea.setWrapText(true);
        reasonsArea.setPrefRowCount(7);

        hourSpinner.setEditable(true);
        deltaSpinner.setEditable(true);
        hourSpinner.setPrefWidth(75);
        deltaSpinner.setPrefWidth(85);
        Button add = new Button("Add evidence");
        add.setOnAction(e -> addEvidence());
        Label hourLabel = new Label("Hour");
        Label alertsLabel = new Label("Extra alerts");
        HBox evidence = new HBox(8, hourLabel, hourSpinner, alertsLabel, deltaSpinner, add);
        evidence.setAlignment(Pos.CENTER_LEFT);

        Label note = new Label("Adding alerts re-scores the host and moves its incident in the red-black tree.");
        note.setWrapText(true);
        note.setTextFill(Color.web(GREY));
        note.setMinHeight(Region.USE_PREF_SIZE);

        VBox left = new VBox(8, sectionTitle("All incidents (highest risk first)"), table,
                sectionTitle("Why this score"), reasonsArea,
                sectionTitle("Simulate new evidence for the selected host"), evidence, note);
        left.setPadding(new Insets(12));
        VBox.setVgrow(table, Priority.ALWAYS);

        patternsArea.setEditable(false);
        patternsArea.setFont(Font.font("Monospaced", 12));
        patternsArea.setPrefRowCount(8);
        Label patternHelp = new Label("A '.' stands for exactly one unknown character, e.g. p.wershell finds powershell.");
        patternHelp.setWrapText(true);
        patternHelp.setTextFill(Color.web(GREY));
        patternHelp.setMinHeight(Region.USE_PREF_SIZE);

        iocField.setPromptText("type the start of an indicator, e.g. update or 203.0");
        iocField.textProperty().addListener((o, a, b) -> updateIocResults());
        Label iocHelp = new Label("Searches the known-indicator trie by prefix. A trailing * marks a prefix rule.");
        iocHelp.setWrapText(true);
        iocHelp.setTextFill(Color.web(GREY));
        iocHelp.setMinHeight(Region.USE_PREF_SIZE);

        VBox right = new VBox(8, sectionTitle("Suspicious command patterns (wildcard hunting)"), patternHelp,
                patternsArea, sectionTitle("Indicator search (prefix trie)"), iocHelp, iocField, iocResults);
        right.setPadding(new Insets(12));
        VBox.setVgrow(iocResults, Priority.ALWAYS);
        right.setPrefWidth(480);

        return new TwoColumns(left, right);
    }

    /** Simple two-column layout (left grows, right has a fixed width). */
    private static final class TwoColumns extends BorderPane {
        TwoColumns(Region left, Region right) {
            setCenter(left);
            setRight(right);
        }
    }

    // ---- tab 3: containment -----------------------------------------------------------------

    private BorderPane buildContainment() {
        ToggleGroup group = new ToggleGroup();
        for (ToggleButton b : new ToggleButton[]{scenarioA, scenarioB}) {
            b.setToggleGroup(group);
            b.setMinWidth(300);
            b.setAlignment(Pos.CENTER_LEFT);
            b.setStyle("-fx-font-size: 13px;");
        }
        scenarioA.setSelected(true);
        scenarioA.setOnAction(e -> chooseScenario(DashboardModel.Scenario.STRICT));
        scenarioB.setOnAction(e -> chooseScenario(DashboardModel.Scenario.RELAXED));
        // keep one button always selected
        group.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null && old != null) {
                old.setSelected(true);
            }
        });

        Label help = new Label("Pick a scenario to see which links to block or hosts to isolate "
                + "(found with max flow / min cut).");
        help.setTextFill(Color.web(GREY));
        HBox choices = new HBox(12, scenarioA, scenarioB);
        VBox top = new VBox(8, help, choices);
        top.setPadding(new Insets(12, 12, 4, 12));

        VBox left = new VBox(6, containmentGraph.holder, legend(true));
        left.setPadding(new Insets(6, 0, 6, 12));
        VBox.setVgrow(containmentGraph.holder, Priority.ALWAYS);

        planBox.setPadding(new Insets(12));
        planBox.setPrefWidth(380);
        ScrollPane scroll = new ScrollPane(planBox);
        scroll.setFitToWidth(true);
        scroll.setPrefWidth(400);

        BorderPane pane = new BorderPane();
        pane.setTop(top);
        pane.setCenter(left);
        pane.setRight(scroll);
        return pane;
    }

    // ---- tab 4: benchmarks ------------------------------------------------------------------

    private BorderPane buildBenchmarks() {
        benchArea.setEditable(false);
        benchArea.setFont(Font.font("Monospaced", 12));
        benchArea.setText("Press \"Run benchmarks\" to compare:\n"
                + "  - Edmonds-Karp and Ford-Fulkerson against a brute-force minimum cut\n"
                + "  - prefix trie, wildcard dictionary and segment tree against plain scans\n"
                + "  - red-black tree against java.util.TreeMap\n\n"
                + "It uses generated (synthetic) data and takes a few seconds.");
        benchProgress.setVisible(false);
        benchProgress.setPrefSize(24, 24);
        benchButton.setOnAction(e -> runBenchmarks());
        HBox bar = new HBox(10, benchButton, benchProgress);
        bar.setAlignment(Pos.CENTER_LEFT);

        validationLabel.setWrapText(true);
        VBox top = new VBox(8, sectionTitle("Quick check on the current network"), validationLabel, bar);
        top.setPadding(new Insets(12));

        BorderPane pane = new BorderPane();
        pane.setTop(top);
        BorderPane.setMargin(benchArea, new Insets(0, 12, 12, 12));
        pane.setCenter(benchArea);
        return pane;
    }

    private void runBenchmarks() {
        benchButton.setDisable(true);
        benchProgress.setVisible(true);
        benchArea.setText("Running benchmarks...");
        Thread t = new Thread(() -> {
            String text;
            PrintStream old = System.out;
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            synchronized (DashboardApp.class) {
                try (PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8)) {
                    System.setOut(ps);
                    Benchmarks.runAll();
                } catch (RuntimeException ex) {
                    buf.writeBytes(("\nBenchmark failed: " + ex.getMessage()).getBytes(StandardCharsets.UTF_8));
                } finally {
                    System.setOut(old);
                }
            }
            text = buf.toString(StandardCharsets.UTF_8).trim();
            Platform.runLater(() -> {
                benchArea.setText(text);
                benchButton.setDisable(false);
                benchProgress.setVisible(false);
            });
        }, "benchmarks");
        t.setDaemon(true);
        t.start();
    }

    // ---- actions ----------------------------------------------------------------------------

    private void runAnalysis() {
        try {
            model.analyse(compromisedField.getText(), targetField.getText(),
                    fromSpinner.getValue(), toSpinner.getValue());
            setStatus("Analysed. Incident tree balanced: " + model.isBalanced(), true);
            refreshAll(null);
        } catch (IllegalArgumentException ex) {
            setStatus("Error: " + ex.getMessage(), false);
        }
    }

    private void addEvidence() {
        if (selectedHost == null) {
            setStatus("Select an incident first.", false);
            return;
        }
        try {
            Incident before = model.incidentFor(selectedHost);
            Incident after = model.addEvidence(selectedHost, hourSpinner.getValue(), deltaSpinner.getValue());
            setStatus(String.format("%s: risk %d -> %d (tree balanced: %s)", selectedHost,
                    before == null ? 0 : before.riskScore(), after.riskScore(), model.isBalanced()), true);
            refreshAll(selectedHost);
        } catch (IllegalArgumentException ex) {
            setStatus("Error: " + ex.getMessage(), false);
        }
    }

    private void chooseScenario(DashboardModel.Scenario s) {
        containmentGraph.scenario = s;
        containmentGraph.redraw();
        fillPlan(s);
    }

    private void setStatus(String text, boolean ok) {
        status.setStyle("-fx-text-fill: " + (ok ? GREEN : RED) + ";");
        status.setText(text);
    }

    private void refreshAll(String keepHost) {
        List<Incident> ranked = model.ranked();
        table.setItems(FXCollections.observableArrayList(ranked));

        String host = keepHost != null ? keepHost : selectedHost;
        boolean found = false;
        for (Incident i : ranked) {
            if (i.host().equals(host)) {
                found = true;
            }
        }
        selectedHost = found ? host : (ranked.isEmpty() ? null : ranked.get(0).host());

        // investigation: patterns + indicator search
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, List<String>> e : model.patternMatches().entrySet()) {
            sb.append(String.format("%-14s ->  %s%n", e.getKey(),
                    e.getValue().isEmpty() ? "(no match)" : String.join(", ", e.getValue())));
        }
        patternsArea.setText(sb.toString());
        updateIocResults();

        // containment: scenario buttons and plan
        ContainmentPlan a = model.plan(DashboardModel.Scenario.STRICT, false);
        ContainmentPlan b = model.plan(DashboardModel.Scenario.RELAXED, false);
        scenarioA.setText("Scenario A  -  " + costText(a) + "\nKeep compromised hosts online, cut the network downstream");
        scenarioB.setText("Scenario B  -  " + costText(b) + "\nAllow isolating the compromised host itself");
        DashboardModel.Scenario shown = scenarioB.isSelected()
                ? DashboardModel.Scenario.RELAXED : DashboardModel.Scenario.STRICT;
        containmentGraph.scenario = shown;
        fillPlan(shown);

        // benchmarks: quick validation
        ContainmentPlan aFf = model.plan(DashboardModel.Scenario.STRICT, true);
        ContainmentPlan bFf = model.plan(DashboardModel.Scenario.RELAXED, true);
        boolean agree = a.totalCost() == aFf.totalCost() && b.totalCost() == bFf.totalCost();
        validationLabel.setText("Edmonds-Karp and Ford-Fulkerson find the same minimum cost on this network: "
                + (agree ? "yes" : "NO - investigate")
                + "   (Scenario A " + costText(a) + ", Scenario B " + costText(b) + ")");

        refreshSelectionViews();
    }

    private static String costText(ContainmentPlan p) {
        return p.feasible() ? "cost " + p.totalCost() : "no finite cost";
    }

    private void selectHost(String host) {
        if (host == null) {
            return;
        }
        selectedHost = host;
        refreshSelectionViews();
    }

    private void refreshSelectionViews() {
        // table row
        updatingSelection = true;
        for (Incident i : table.getItems()) {
            if (i.host().equals(selectedHost)) {
                table.getSelectionModel().select(i);
            }
        }
        updatingSelection = false;

        Incident sel = selectedHost == null ? null : model.incidentFor(selectedHost);
        if (sel == null) {
            reasonsArea.clear();
            chart.getData().clear();
            chart.setTitle("");
            selectionSummary.setText("");
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(sel.host()).append("  |  risk ").append(sel.riskScore())
                    .append("  (").append(level(sel.riskScore())).append(")\n");
            for (String r : sel.reasons()) {
                sb.append(" - ").append(r).append("\n");
            }
            reasonsArea.setText(sb.toString());
            selectionSummary.setText(sel.host() + ": risk " + sel.riskScore() + " (" + level(sel.riskScore()) + ")");
            updateChart(sel.host());
        }
        rebuildCards();
        overviewGraph.redraw();
        containmentGraph.redraw();
    }

    private void updateIocResults() {
        iocResults.setItems(FXCollections.observableArrayList(model.searchIoc(iocField.getText())));
    }

    // ---- overview widgets -------------------------------------------------------------------

    private void rebuildCards() {
        cardsBox.getChildren().clear();
        List<Incident> ranked = model.ranked();
        for (int i = 0; i < Math.min(5, ranked.size()); i++) {
            cardsBox.getChildren().add(card(ranked.get(i)));
        }
    }

    private HBox card(Incident inc) {
        Label badge = new Label(String.valueOf(inc.riskScore()));
        badge.setMinSize(46, 46);
        badge.setAlignment(Pos.CENTER);
        badge.setStyle("-fx-background-radius: 23; -fx-text-fill: " + textOn(inc.riskScore())
                + "; -fx-font-weight: bold; -fx-font-size: 15px; -fx-background-color: " + levelColor(inc.riskScore()) + ";");
        Label host = new Label(inc.host());
        host.setFont(Font.font(null, FontWeight.BOLD, 14));
        Label lvl = new Label(level(inc.riskScore()) + " priority");
        lvl.setTextFill(Color.web(levelColor(inc.riskScore())));
        Label why = new Label(inc.reasons().isEmpty() ? "" : inc.reasons().get(0));
        why.setTextFill(Color.web(GREY));
        why.setWrapText(true);
        VBox text = new VBox(2, host, lvl, why);
        HBox.setHgrow(text, Priority.ALWAYS);
        HBox box = new HBox(10, badge, text);
        box.setAlignment(Pos.CENTER_LEFT);
        box.setPadding(new Insets(8));
        boolean sel = inc.host().equals(selectedHost);
        box.setStyle("-fx-background-color: " + (sel ? "#e3f2fd" : "#fafafa") + "; -fx-border-color: "
                + (sel ? "#1565c0" : "#cfd8dc") + "; -fx-border-radius: 6; -fx-background-radius: 6;");
        box.setCursor(Cursor.HAND);
        box.setOnMouseClicked(e -> selectHost(inc.host()));
        return box;
    }

    private void updateChart(String host) {
        chart.getData().clear();
        int[] hourly = model.hourly(host);
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        for (int h = 0; h < hourly.length; h++) {
            XYChart.Data<String, Number> d = new XYChart.Data<>(String.valueOf(h), hourly[h]);
            boolean inWindow = h >= model.from() && h <= model.to();
            d.nodeProperty().addListener((o, old, node) -> {
                if (node != null) {
                    node.setStyle("-fx-bar-fill: " + (inWindow ? "#d84315" : "#b0bec5") + ";");
                }
            });
            series.getData().add(d);
        }
        chart.getData().add(series);
        chart.setTitle(String.format("%s: alerts per hour (hours %d-%d: total %d, peak %d)", host,
                model.from(), model.to(), model.windowTotal(host), model.windowPeak(host)));
    }

    // ---- containment widgets ----------------------------------------------------------------

    private void fillPlan(DashboardModel.Scenario s) {
        planBox.getChildren().clear();
        ContainmentPlan ek = model.plan(s, false);
        ContainmentPlan ff = model.plan(s, true);
        String name = s == DashboardModel.Scenario.STRICT ? "Scenario A" : "Scenario B";
        planBox.getChildren().add(sectionTitle(name + " - recommended actions"));
        if (!ek.feasible()) {
            Label none = new Label("No finite-cost containment exists: an uncuttable path reaches a target.");
            none.setWrapText(true);
            none.setTextFill(Color.web(RED));
            planBox.getChildren().add(none);
            return;
        }
        Label cost = new Label("Total cost: " + ek.totalCost());
        cost.setFont(Font.font(null, FontWeight.BOLD, 22));
        planBox.getChildren().add(cost);
        for (ContainmentPlan.Action a : ek.actions()) {
            boolean isolate = a.type().equals("ISOLATE_HOST");
            Label l = new Label((isolate ? "ISOLATE  " : "BLOCK  ") + a.description()
                    .replace("Isolate host ", "").replace("Block link ", "") + "   (cost " + a.cost() + ")");
            l.setWrapText(true);
            l.setStyle("-fx-border-color: " + ORANGE + "; -fx-border-width: 0 0 0 4; -fx-padding: 4 8 4 8;");
            planBox.getChildren().add(l);
        }
        Label affected = new Label("Affected assets: " + String.join(", ", ek.affectedAssets()));
        affected.setWrapText(true);
        affected.setMinHeight(Region.USE_PREF_SIZE);
        Label verified = new Label("Verified: " + (ek.verified()
                ? "yes - no protected target is reachable after the cut"
                : "NO - a target is still reachable"));
        verified.setWrapText(true);
        verified.setMinHeight(Region.USE_PREF_SIZE);
        verified.setTextFill(Color.web(ek.verified() ? GREEN : RED));
        Label algos = new Label(String.format("%s %.3f ms  |  %s %.3f ms%nSame cost from both algorithms: %s",
                ek.algorithm(), ek.nanos() / 1e6, ff.algorithm(), ff.nanos() / 1e6,
                ek.totalCost() == ff.totalCost() ? "yes" : "NO"));
        algos.setTextFill(Color.web(GREY));
        algos.setWrapText(true);
        algos.setMinHeight(Region.USE_PREF_SIZE);
        planBox.getChildren().addAll(affected, verified, new Region(), algos);
    }

    // ---- shared helpers ---------------------------------------------------------------------

    private static Label sectionTitle(String text) {
        Label l = new Label(text);
        l.setFont(Font.font(null, FontWeight.BOLD, 14));
        return l;
    }

    private static String level(int score) {
        if (score >= 80) {
            return "Critical";
        }
        if (score >= 60) {
            return "High";
        }
        if (score >= 30) {
            return "Medium";
        }
        return "Low";
    }

    private static String levelColor(int score) {
        if (score >= 80) {
            return RED;
        }
        if (score >= 60) {
            return ORANGE;
        }
        if (score >= 30) {
            return YELLOW;
        }
        return GREEN;
    }

    private static String textOn(int score) {
        return score >= 30 && score < 60 ? "black" : "white";
    }

    private static HBox legend(boolean withCut) {
        HBox box = new HBox(16);
        box.setAlignment(Pos.CENTER_LEFT);
        box.getChildren().add(legendItem(RED, "Attack path / critical risk"));
        if (withCut) {
            box.getChildren().add(legendItem(ORANGE, "Blocked link / isolated host"));
        }
        box.getChildren().add(legendItem(BLUE, "Protected target (blue ring)"));
        box.getChildren().add(legendItem("#b71c1c", "Compromised (dark red ring)"));
        Label fill = new Label("Node colour = risk: green low, yellow medium, orange high, red critical");
        fill.setTextFill(Color.web(GREY));
        VBox all = new VBox(4, box, fill);
        HBox wrap = new HBox(all);
        wrap.setPadding(new Insets(2, 0, 0, 0));
        return wrap;
    }

    private static HBox legendItem(String color, String text) {
        Region swatch = new Region();
        swatch.setMinSize(14, 14);
        swatch.setMaxSize(14, 14);
        swatch.setStyle("-fx-background-color: " + color + ";");
        HBox item = new HBox(6, swatch, new Label(text));
        item.setAlignment(Pos.CENTER_LEFT);
        return item;
    }

    private static long edgeKey(int n, int a, int b) {
        return (long) Math.min(a, b) * n + Math.max(a, b);
    }

    // ---- network graph ----------------------------------------------------------------------

    /** A canvas that draws the network. The containment version also draws the chosen cut. */
    private final class GraphView {
        final Canvas canvas = new Canvas(600, 400);
        final Pane holder = new Pane(canvas);
        final boolean showCut;
        DashboardModel.Scenario scenario = DashboardModel.Scenario.NONE;
        private double[] nx = new double[0];
        private double[] ny = new double[0];

        GraphView(boolean showCut) {
            this.showCut = showCut;
            holder.setMinSize(260, 260);
            canvas.widthProperty().bind(holder.widthProperty());
            canvas.heightProperty().bind(holder.heightProperty());
            canvas.widthProperty().addListener(o -> redraw());
            canvas.heightProperty().addListener(o -> redraw());
            canvas.setOnMouseClicked(e -> pick(e.getX(), e.getY()));
        }

        private void pick(double x, double y) {
            for (int i = 0; i < nx.length; i++) {
                if (Math.hypot(x - nx[i], y - ny[i]) <= NODE_R + 4) {
                    String host = model.topology().asset(i).name();
                    if (model.incidentFor(host) != null) {
                        selectHost(host);
                    } else {
                        setStatus(host + " has no incident in the queue.", true);
                    }
                    return;
                }
            }
        }

        void redraw() {
            GraphicsContext g = canvas.getGraphicsContext2D();
            double w = canvas.getWidth();
            double h = canvas.getHeight();
            g.setFill(Color.web("#fafafa"));
            g.fillRect(0, 0, w, h);
            if (model == null || !model.isAnalysed()) {
                return;
            }
            Topology topo = model.topology();
            int n = topo.size();
            nx = new double[n];
            ny = new double[n];
            double radius = Math.max(60, Math.min(w, h) / 2 - 48);
            for (int i = 0; i < n; i++) {
                double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
                nx[i] = w / 2 + radius * Math.cos(angle);
                ny[i] = h / 2 + radius * Math.sin(angle);
            }

            Set<Long> pathEdges = new HashSet<>();
            for (List<Integer> p : model.attackPaths()) {
                for (int i = 0; i + 1 < p.size(); i++) {
                    pathEdges.add(edgeKey(n, p.get(i), p.get(i + 1)));
                }
            }
            ContainmentPlan plan = showCut ? model.plan(scenario, false) : null;
            List<int[]> blocked = model.blockedLinks(plan);
            Set<Integer> isolated = model.isolatedHosts(plan);

            g.setLineCap(StrokeLineCap.ROUND);
            g.setLineDashes((double[]) null);
            g.setStroke(Color.web("#b0bec5"));
            g.setLineWidth(1.5);
            for (Link l : topo.links()) {
                g.strokeLine(nx[l.from()], ny[l.from()], nx[l.to()], ny[l.to()]);
            }
            g.setStroke(Color.web(RED));
            g.setLineWidth(4);
            for (Link l : topo.links()) {
                if (pathEdges.contains(edgeKey(n, l.from(), l.to()))) {
                    g.strokeLine(nx[l.from()], ny[l.from()], nx[l.to()], ny[l.to()]);
                }
            }
            g.setStroke(Color.web(ORANGE));
            g.setLineWidth(5);
            g.setLineDashes(10, 8);
            for (int[] b : blocked) {
                g.strokeLine(nx[b[0]], ny[b[0]], nx[b[1]], ny[b[1]]);
            }
            g.setLineDashes((double[]) null);
            g.setLineWidth(4);
            for (int[] b : blocked) {
                double mx = (nx[b[0]] + nx[b[1]]) / 2;
                double my = (ny[b[0]] + ny[b[1]]) / 2;
                g.strokeLine(mx - 8, my - 8, mx + 8, my + 8);
                g.strokeLine(mx - 8, my + 8, mx + 8, my - 8);
            }

            g.setTextAlign(TextAlignment.CENTER);
            for (int i = 0; i < n; i++) {
                String name = topo.asset(i).name();
                Incident inc = model.incidentFor(name);
                boolean isSelected = name.equals(selectedHost);
                double r = isSelected ? NODE_R + 4 : NODE_R;
                g.setFill(inc == null ? Color.web("#cfd8dc") : Color.web(levelColor(inc.riskScore())));
                g.fillOval(nx[i] - r, ny[i] - r, 2 * r, 2 * r);
                Color ring = Color.web("#78909c");
                double ringWidth = 1.5;
                if (model.sources().contains(i)) {
                    ring = Color.web("#b71c1c");
                    ringWidth = 5;
                } else if (model.targets().contains(i)) {
                    ring = Color.web(BLUE);
                    ringWidth = 5;
                }
                if (isSelected && ringWidth < 3) {
                    ring = Color.BLACK;
                    ringWidth = 3;
                }
                g.setStroke(ring);
                g.setLineWidth(ringWidth);
                g.strokeOval(nx[i] - r, ny[i] - r, 2 * r, 2 * r);
                if (isolated.contains(i)) {
                    g.setStroke(Color.web(ORANGE));
                    g.setLineWidth(4);
                    g.strokeOval(nx[i] - r - 7, ny[i] - r - 7, 2 * r + 14, 2 * r + 14);
                    g.strokeLine(nx[i] - r, ny[i] - r, nx[i] + r, ny[i] + r);
                    g.strokeLine(nx[i] - r, ny[i] + r, nx[i] + r, ny[i] - r);
                }
                if (inc != null) {
                    g.setFill("black".equals(textOn(inc.riskScore())) ? Color.BLACK : Color.WHITE);
                    g.setFont(Font.font(null, FontWeight.BOLD, 12));
                    g.fillText(String.valueOf(inc.riskScore()), nx[i], ny[i] + 4);
                }
                g.setFill(Color.web("#263238"));
                g.setFont(Font.font(null, isSelected ? FontWeight.BOLD : FontWeight.NORMAL, 12));
                g.fillText(name, nx[i], ny[i] + r + 16);
            }
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}