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
import javafx.scene.Node;
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
import javafx.scene.control.TitledPane;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JavaFX dashboard with four tabs: Overview, Investigation, Containment and Benchmarks.
 * Run with: mvn javafx:run
 */
public final class DashboardApp extends Application {
    private static final double NODE_R = 17;

    // Colour is reserved for risk. Everything else is grey or ink.
    private static final String INK = "#20242a";
    private static final String MUTED = "#5d6671";
    private static final String RULE = "#cfd5dc";
    private static final String TARGET = "#0b4f6c";
    private static final String OK = "#2a6f4e";
    private static final String SEV_LOW = "#aab5c1";
    private static final String SEV_MED = "#e2a93b";
    private static final String SEV_HIGH = "#cf5c2a";
    private static final String SEV_CRIT = "#a3202a";

    // Typefaces are picked from what is installed, with sensible fallbacks.
    private static String bodyFont = "System";
    private static String numberFont = "System";
    private static String monoFont = "Monospaced";

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
    private final VBox triageList = new VBox();
    private final HBox statsBox = new HBox(8);
    private final Label statsTitle = new Label();
    private final CategoryAxis hourAxis = new CategoryAxis();
    private final NumberAxis countAxis = new NumberAxis();
    private final BarChart<String, Number> chart = new BarChart<>(hourAxis, countAxis);

    // investigation
    private final TableView<Incident> table = new TableView<>();
    private final VBox explainBox = new VBox(8);
    private final TextArea patternsArea = new TextArea();
    private final TextField iocField = new TextField();
    private final Label iocCount = new Label();
    private final ListView<String> iocResults = new ListView<>();
    private final Spinner<Integer> hourSpinner = new Spinner<>(0, 23, 12);
    private final Spinner<Integer> deltaSpinner = new Spinner<>(1, 500, 30);

    // containment
    private final GraphView containmentGraph = new GraphView(true);
    private final ToggleButton scenarioA = new ToggleButton();
    private final ToggleButton scenarioB = new ToggleButton();
    private final VBox planBox = new VBox(10);

    // benchmarks
    private final Button benchButton = new Button("Run benchmarks");
    private final ProgressIndicator benchProgress = new ProgressIndicator();
    private final VBox summaryBox = new VBox();
    private final TextArea benchArea = new TextArea();

    @Override
    public void start(Stage stage) {
        chooseFonts();
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
        root.setStyle("-fx-font-family: '" + bodyFont + "'; -fx-font-size: 13px;");

        Scene scene = new Scene(root, 1280, 840);
        URL css = DashboardApp.class.getResource("/breachpath.css");
        if (css != null) {
            scene.getStylesheets().add(css.toExternalForm());
        }
        stage.setTitle("BreachPath - Enterprise Breach Analysis & Containment");
        stage.setScene(scene);
        stage.show();
        runAnalysis();
    }

    /**
     * Loads the bundled fonts: Fira Sans for text and numbers, IBM Plex Mono for machine
     * strings (both under the SIL Open Font License, see resources/fonts). Bundling avoids the
     * platform font lookup, which picks the wrong face for some macOS families. If the files are
     * missing the dashboard falls back to the system fonts.
     */
    private static void chooseFonts() {
        String body = loadFamily("/fonts/FiraSans-Regular.ttf");
        loadFamily("/fonts/FiraSans-Bold.ttf");
        String mono = loadFamily("/fonts/IBMPlexMono-Regular.ttf");
        bodyFont = body != null ? body : "System";
        numberFont = bodyFont;
        monoFont = mono != null ? mono : "Monospaced";
    }

    private static String loadFamily(String resource) {
        URL url = DashboardApp.class.getResource(resource);
        if (url == null) {
            return null;
        }
        Font f = Font.loadFont(url.toExternalForm(), 12);
        return f == null ? null : f.getFamily();
    }

    private static Tab tab(String title, Node content) {
        Tab t = new Tab(title, content);
        t.setClosable(false);
        return t;
    }

    // ---- top bar ----------------------------------------------------------------------------

    private VBox buildTopBar() {
        Label title = new Label("BreachPath");
        font(title, numberFont, FontWeight.BOLD, 26);
        Label subtitle = muted("Breach analysis and containment");
        HBox titles = new HBox(14, title, subtitle);
        titles.setAlignment(Pos.BASELINE_LEFT);

        fromSpinner.setEditable(true);
        toSpinner.setEditable(true);
        fromSpinner.setPrefWidth(74);
        toSpinner.setPrefWidth(74);
        compromisedField.setPrefWidth(180);
        compromisedField.setPromptText("WS-Alice,WS-Bob");
        targetField.setPrefWidth(180);
        targetField.setPromptText("DB-PROD,CLOUD-ADMIN");
        Button run = new Button("Analyse");
        run.getStyleClass().add("primary");
        run.setDefaultButton(true);
        run.setOnAction(e -> runAnalysis());
        status.setWrapText(true);
        HBox.setHgrow(status, Priority.ALWAYS);

        HBox controls = new HBox(8, new Label("Compromised host"), compromisedField, new Label("Protected target"),
                targetField, new Label("Hours"), fromSpinner, new Label("to"), toSpinner, run, status);
        controls.setAlignment(Pos.CENTER_LEFT);

        VBox box = new VBox(10, titles, controls);
        box.setPadding(new Insets(12, 16, 8, 16));
        return box;
    }

    // ---- tab 1: overview --------------------------------------------------------------------

    private BorderPane buildOverview() {
        chart.setAnimated(false);
        chart.setLegendVisible(false);
        chart.setCategoryGap(3);
        hourAxis.setLabel("hour of day");
        countAxis.setLabel("alerts");
        chart.setPrefHeight(190);

        VBox left = new VBox(8, heading("Network map"), overviewGraph.holder, legend(false));
        left.setPadding(new Insets(14, 8, 6, 16));
        VBox.setVgrow(overviewGraph.holder, Priority.ALWAYS);

        Label hint = muted("Click a row or a host on the map.");
        hint.setWrapText(true);
        hint.setMinHeight(Region.USE_PREF_SIZE);
        font(statsTitle, bodyFont, FontWeight.BOLD, 15);
        VBox.setMargin(statsTitle, new Insets(16, 0, 0, 0));
        VBox right = new VBox(8, heading("Incidents by risk"), triageList, hint, statsTitle, statsBox);
        right.setPadding(new Insets(14, 16, 6, 8));
        right.setPrefWidth(360);

        VBox bottom = new VBox(chart);
        bottom.setPadding(new Insets(0, 16, 8, 16));

        BorderPane pane = new BorderPane();
        pane.setCenter(left);
        pane.setRight(right);
        pane.setBottom(bottom);
        return pane;
    }

    // ---- tab 2: investigation ---------------------------------------------------------------

    private BorderPane buildInvestigation() {
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
        TableColumn<Incident, String> whyCol = new TableColumn<>("Largest factor");
        whyCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(
                c.getValue().reasons().isEmpty() ? "" : c.getValue().reasons().get(0)));
        whyCol.setPrefWidth(260);
        table.getColumns().add(hostCol);
        table.getColumns().add(riskCol);
        table.getColumns().add(levelCol);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.setPrefHeight(190);
        table.getSelectionModel().selectedItemProperty().addListener((o, a, b) -> {
            if (!updatingSelection && b != null) {
                selectHost(b.host());
            }
        });

        ScrollPane explainScroll = new ScrollPane(explainBox);
        explainScroll.setFitToWidth(true);
        explainScroll.setPrefHeight(292);
        explainBox.setPadding(new Insets(12, 14, 12, 14));
        explainScroll.setStyle("-fx-background-color: #ffffff; -fx-border-color: " + RULE + ";");
        explainBox.setStyle("-fx-background-color: #ffffff;");

        hourSpinner.setEditable(true);
        deltaSpinner.setEditable(true);
        hourSpinner.setPrefWidth(76);
        deltaSpinner.setPrefWidth(86);
        Button add = new Button("Add evidence");
        add.setOnAction(e -> addEvidence());
        HBox evidence = new HBox(10, new Label("Hour"), hourSpinner, new Label("Extra alerts"), deltaSpinner, add);
        evidence.setAlignment(Pos.CENTER_LEFT);
        Label evidenceNote = muted("Adds alerts at that hour and re-scores the host.");
        evidenceNote.setWrapText(true);
        evidenceNote.setMinHeight(Region.USE_PREF_SIZE);

        VBox left = new VBox(14, heading("Incidents"), table, heading("Selected incident"), explainScroll,
                heading("Add new evidence"), new VBox(6, evidence, evidenceNote));
        left.setPadding(new Insets(16, 10, 16, 18));
        VBox.setVgrow(explainScroll, Priority.NEVER);

        patternsArea.setEditable(false);
        font(patternsArea, monoFont, FontWeight.NORMAL, 12);
        patternsArea.setPrefRowCount(5);
        patternsArea.setWrapText(false);
        Label patternHelp = muted("A dot stands for exactly one unknown character.");
        patternHelp.setWrapText(true);
        patternHelp.setMinHeight(Region.USE_PREF_SIZE);

        iocField.setPromptText("Start of an indicator, e.g. update or 203.0");
        iocField.textProperty().addListener((o, a, b) -> updateIocResults());
        iocResults.setFixedCellSize(28);
        iocResults.setPrefHeight(150);
        iocResults.setMaxHeight(150);
        iocCount.setTextFill(Color.web(MUTED));

        VBox right = new VBox(14,
                heading("Wildcard command patterns"), new VBox(6, patternHelp, patternsArea),
                heading("Indicator search"), new VBox(6, iocField, iocResults, iocCount));
        right.setPadding(new Insets(16, 18, 16, 10));
        right.setPrefWidth(440);

        BorderPane pane = new BorderPane();
        pane.setCenter(left);
        pane.setRight(right);
        return pane;
    }

    // ---- tab 3: containment -----------------------------------------------------------------

    private BorderPane buildContainment() {
        ToggleGroup group = new ToggleGroup();
        for (ToggleButton b : new ToggleButton[]{scenarioA, scenarioB}) {
            b.setToggleGroup(group);
            b.getStyleClass().add("scenario");
            b.setMinWidth(330);
            b.setAlignment(Pos.CENTER_LEFT);
        }
        scenarioA.setSelected(true);
        scenarioA.setOnAction(e -> chooseScenario(DashboardModel.Scenario.STRICT));
        scenarioB.setOnAction(e -> chooseScenario(DashboardModel.Scenario.RELAXED));
        group.selectedToggleProperty().addListener((o, old, now) -> {
            if (now == null && old != null) {
                old.setSelected(true);
            }
        });

        HBox choices = new HBox(14, scenarioA, scenarioB);
        choices.setMaxHeight(Region.USE_PREF_SIZE);
        scenarioA.setMaxHeight(Region.USE_PREF_SIZE);
        scenarioB.setMaxHeight(Region.USE_PREF_SIZE);
        VBox top = new VBox(8, choices);
        top.setPadding(new Insets(14, 16, 4, 16));

        VBox left = new VBox(8, containmentGraph.holder, legend(true));
        left.setPadding(new Insets(6, 8, 6, 16));
        VBox.setVgrow(containmentGraph.holder, Priority.ALWAYS);

        planBox.setPadding(new Insets(6, 16, 16, 8));
        ScrollPane scroll = new ScrollPane(planBox);
        scroll.setFitToWidth(true);
        scroll.setPrefWidth(380);

        BorderPane pane = new BorderPane();
        pane.setTop(top);
        pane.setCenter(left);
        pane.setRight(scroll);
        return pane;
    }

    // ---- tab 4: benchmarks ------------------------------------------------------------------

    private BorderPane buildBenchmarks() {
        benchProgress.setVisible(false);
        benchProgress.setPrefSize(22, 22);
        benchButton.getStyleClass().add("primary");
        benchButton.setOnAction(e -> runBenchmarks());
        Label note = muted("Generated data, one run per size. Times change a little from run to run.");
        HBox bar = new HBox(12, benchButton, benchProgress, note);
        bar.setAlignment(Pos.CENTER_LEFT);

        summaryBox.getChildren().add(muted("Press \"Run benchmarks\". It takes a few seconds."));

        benchArea.setEditable(false);
        font(benchArea, monoFont, FontWeight.NORMAL, 12);
        benchArea.setPrefRowCount(16);
        TitledPane details = new TitledPane("Detailed timings", benchArea);
        details.setExpanded(false);
        details.setAnimated(false);

        VBox content = new VBox(18,
                new VBox(8, heading("The five concepts"), bar, summaryBox),
                details);
        content.setPadding(new Insets(16, 18, 16, 18));
        ScrollPane scroll = new ScrollPane(content);
        scroll.setFitToWidth(true);

        BorderPane pane = new BorderPane();
        pane.setCenter(scroll);
        return pane;
    }

    private void runBenchmarks() {
        benchButton.setDisable(true);
        benchProgress.setVisible(true);
        summaryBox.getChildren().setAll(muted("Running..."));
        Thread t = new Thread(() -> {
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
            String text = buf.toString(StandardCharsets.UTF_8).trim();
            Platform.runLater(() -> {
                showBenchmarks(text);
                benchButton.setDisable(false);
                benchProgress.setVisible(false);
            });
        }, "benchmarks");
        t.setDaemon(true);
        t.start();
    }

    private void showBenchmarks(String text) {
        benchArea.setText(BenchmarkSummary.detailForDisplay(text));
        GridPane grid = new GridPane();
        ColumnConstraints c1 = new ColumnConstraints(190);
        ColumnConstraints c2 = new ColumnConstraints();
        c2.setHgrow(Priority.ALWAYS);
        ColumnConstraints c3 = new ColumnConstraints(86);
        ColumnConstraints c4 = new ColumnConstraints();
        c4.setHgrow(Priority.ALWAYS);
        grid.getColumnConstraints().addAll(c1, c2, c3, c4);
        String[] heads = {"Concept", "Check", "Result", "Performance"};
        for (int c = 0; c < heads.length; c++) {
            Label h = cell(heads[c], true, "#eef1f4");
            grid.add(h, c, 0);
        }
        int r = 1;
        for (BenchmarkSummary.Row row : BenchmarkSummary.parse(text)) {
            grid.add(cell(row.concept(), true, "#fbfcfd"), 0, r);
            grid.add(cell(row.check(), false, "#fbfcfd"), 1, r);
            Label result = cell(row.passed() ? "Pass" : "Fail", true, "#fbfcfd");
            result.setTextFill(Color.web(row.passed() ? OK : SEV_CRIT));
            grid.add(result, 2, r);
            grid.add(cell(row.performance(), false, "#fbfcfd"), 3, r);
            r++;
        }
        grid.setStyle("-fx-border-color: " + RULE + ";");
        summaryBox.getChildren().setAll(grid);
    }

    private Label cell(String text, boolean bold, String fill) {
        Label l = new Label(text);
        l.setWrapText(true);
        l.setMaxWidth(Double.MAX_VALUE);
        l.setMaxHeight(Double.MAX_VALUE);
        l.setMinHeight(Region.USE_PREF_SIZE);
        font(l, bodyFont, bold ? FontWeight.BOLD : FontWeight.NORMAL, 13);
        l.setStyle(l.getStyle() + cellStyle(fill));
        GridPane.setFillWidth(l, true);
        GridPane.setFillHeight(l, true);
        return l;
    }

    private static String cellStyle(String fill) {
        return "-fx-background-color: " + fill + "; -fx-padding: 10 12 10 12; "
                + "-fx-border-color: transparent transparent " + RULE + " transparent;";
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
            setStatus(String.format("%s: risk %d to %d (tree balanced: %s)", selectedHost,
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
        status.setStyle("-fx-text-fill: " + (ok ? OK : SEV_CRIT) + ";");
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

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, List<String>> e : model.patternMatches().entrySet()) {
            sb.append(String.format("%-13s %s%n", e.getKey(),
                    e.getValue().isEmpty() ? "no match" : String.join(", ", e.getValue())));
        }
        patternsArea.setText(sb.toString());
        updateIocResults();

        ContainmentPlan a = model.plan(DashboardModel.Scenario.STRICT, false);
        ContainmentPlan b = model.plan(DashboardModel.Scenario.RELAXED, false);
        fillScenarioCard(scenarioA, "Scenario A", a, "Compromised hosts stay online");
        fillScenarioCard(scenarioB, "Scenario B", b, "The compromised host itself may be isolated");
        DashboardModel.Scenario shown = scenarioB.isSelected()
                ? DashboardModel.Scenario.RELAXED : DashboardModel.Scenario.STRICT;
        containmentGraph.scenario = shown;
        fillPlan(shown);


        refreshSelectionViews();
    }

    private void fillScenarioCard(ToggleButton card, String name, ContainmentPlan p, String rule) {
        Label title = new Label(name);
        font(title, bodyFont, FontWeight.BOLD, 14);
        Label cost = new Label(p.feasible() ? "Cost " + p.totalCost() : "No finite cost");
        font(cost, numberFont, FontWeight.BOLD, 26);
        VBox box = new VBox(2, title, cost, muted(rule));
        card.setGraphic(box);
        card.setText(null);
    }

    private void selectHost(String host) {
        if (host == null) {
            return;
        }
        selectedHost = host;
        refreshSelectionViews();
    }

    private void refreshSelectionViews() {
        updatingSelection = true;
        for (Incident i : table.getItems()) {
            if (i.host().equals(selectedHost)) {
                table.getSelectionModel().select(i);
            }
        }
        updatingSelection = false;

        Incident sel = selectedHost == null ? null : model.incidentFor(selectedHost);
        if (sel == null) {
            explainBox.getChildren().clear();
            chart.getData().clear();
            chart.setTitle("");
        } else {
            fillExplanation(sel);
            updateChart(sel.host());
        }
        rebuildTriage();
        overviewGraph.redraw();
        containmentGraph.redraw();
    }

    private void updateIocResults() {
        List<String> found = model.searchIoc(iocField.getText());
        iocResults.setItems(FXCollections.observableArrayList(found));
        iocCount.setText(found.size() + (found.size() == 1 ? " indicator" : " indicators"));
    }

    // ---- explanation of one incident --------------------------------------------------------

    private static final Pattern POINTS = Pattern.compile("^(.*?)\\s*\\(\\+(\\d+)\\)\\s*$");

    private void fillExplanation(Incident inc) {
        explainBox.getChildren().clear();
        Label host = new Label(inc.host());
        font(host, numberFont, FontWeight.BOLD, 22);
        Label score = new Label(inc.riskScore() + " of 100");
        font(score, numberFont, FontWeight.BOLD, 22);
        score.setTextFill(Color.web(levelColor(inc.riskScore())));
        Label lvl = muted(level(inc.riskScore()) + " priority");
        HBox head = new HBox(12, host, score, lvl);
        head.setAlignment(Pos.BASELINE_LEFT);
        explainBox.getChildren().add(head);

        int sum = 0;
        for (String reason : inc.reasons()) {
            Matcher m = POINTS.matcher(reason);
            Label pts;
            String text;
            if (m.matches()) {
                int p = Integer.parseInt(m.group(2));
                sum += p;
                pts = new Label("+" + p);
                text = m.group(1);
            } else {
                pts = new Label("note");
                pts.setTextFill(Color.web(MUTED));
                text = reason;
            }
            font(pts, numberFont, FontWeight.BOLD, 16);
            pts.setMinWidth(46);
            Label body = new Label(text);
            body.setWrapText(true);
            body.setMinHeight(Region.USE_PREF_SIZE);
            HBox row = new HBox(10, pts, body);
            row.setAlignment(Pos.BASELINE_LEFT);
            row.setPadding(new Insets(3, 0, 3, 0));
            row.setStyle("-fx-border-color: transparent transparent #e3e7ec transparent;");
            explainBox.getChildren().add(row);
        }
        if (sum > inc.riskScore()) {
            explainBox.getChildren().add(muted("Factors add up to " + sum + "; the score is capped at "
                    + inc.riskScore() + "."));
        }
    }

    // ---- overview widgets -------------------------------------------------------------------

    private void rebuildTriage() {
        triageList.getChildren().clear();
        List<Incident> ranked = model.ranked();
        for (int i = 0; i < Math.min(5, ranked.size()); i++) {
            triageList.getChildren().add(triageRow(ranked.get(i)));
        }
    }

    private HBox triageRow(Incident inc) {
        Region strip = new Region();
        strip.setMinWidth(5);
        strip.setMaxWidth(5);
        strip.setStyle("-fx-background-color: " + levelColor(inc.riskScore()) + ";");
        Label score = new Label(String.valueOf(inc.riskScore()));
        font(score, numberFont, FontWeight.BOLD, 28);
        score.setMinWidth(54);
        Label host = new Label(inc.host());
        font(host, bodyFont, FontWeight.BOLD, 14);
        Label lvl = muted(level(inc.riskScore()));
        HBox first = new HBox(8, host, lvl);
        first.setAlignment(Pos.BASELINE_LEFT);
        Label why = muted(inc.reasons().isEmpty() ? "" : inc.reasons().get(0));
        why.setMaxWidth(250);
        VBox text = new VBox(1, first, why);
        HBox.setHgrow(text, Priority.ALWAYS);
        HBox row = new HBox(10, strip, score, text);
        row.setAlignment(Pos.CENTER_LEFT);
        row.setPadding(new Insets(7, 6, 7, 0));
        row.getStyleClass().add("triage-row");
        if (inc.host().equals(selectedHost)) {
            row.getStyleClass().add("selected");
        }
        row.setCursor(Cursor.HAND);
        row.setOnMouseClicked(e -> selectHost(inc.host()));
        return row;
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
                    node.setStyle("-fx-bar-fill: " + (inWindow ? INK : "#c3ccd5") + ";");
                }
            });
            series.getData().add(d);
        }
        chart.getData().add(series);
        chart.setTitle("Alerts per hour: " + host);
        statsTitle.setText(host);
        statsBox.getChildren().setAll(
                statBox(String.valueOf(model.windowTotal(host)), "Total alerts"),
                statBox(String.valueOf(model.windowPeak(host)), "Peak/hour"),
                statBox(model.from() + "-" + model.to(), "Window"));
    }

    // ---- containment widgets ----------------------------------------------------------------

    private static VBox statBox(String value, String caption) {
        Label v = new Label(value);
        font(v, numberFont, FontWeight.BOLD, 22);
        VBox box = new VBox(0, v, muted(caption));
        box.setPadding(new Insets(5, 10, 5, 10));
        box.setPrefWidth(104);
        box.setMinWidth(0);
        box.setStyle("-fx-background-color: #fbfcfd; -fx-border-color: " + RULE + ";");
        return box;
    }

    private void fillPlan(DashboardModel.Scenario s) {
        planBox.getChildren().clear();
        ContainmentPlan ek = model.plan(s, false);
        String name = s == DashboardModel.Scenario.STRICT ? "Scenario A" : "Scenario B";
        planBox.getChildren().add(heading(name + ": recommended actions"));
        if (!ek.feasible()) {
            Label none = new Label("No finite-cost containment exists. An uncuttable path reaches a target.");
            none.setWrapText(true);
            none.setMinHeight(Region.USE_PREF_SIZE);
            none.setTextFill(Color.web(SEV_CRIT));
            planBox.getChildren().add(none);
            return;
        }
        VBox actions = new VBox();
        for (ContainmentPlan.Action a : ek.actions()) {
            boolean isolate = a.type().equals("ISOLATE_HOST");
            String what = a.description().replace("Isolate host ", "").replace("Block link ", "").replace(" -> ", " to ");
            Label kind = new Label(isolate ? "Isolate" : "Block link");
            font(kind, bodyFont, FontWeight.BOLD, 13);
            kind.setMinWidth(76);
            Label target = new Label(what);
            target.setWrapText(true);
            target.setMinHeight(Region.USE_PREF_SIZE);
            HBox.setHgrow(target, Priority.ALWAYS);
            target.setMaxWidth(Double.MAX_VALUE);
            Label cost = new Label(String.valueOf(a.cost()));
            font(cost, numberFont, FontWeight.BOLD, 16);
            HBox row = new HBox(8, kind, target, cost);
            row.setAlignment(Pos.BASELINE_LEFT);
            row.setPadding(new Insets(7, 0, 7, 0));
            row.setStyle("-fx-border-color: transparent transparent " + RULE + " transparent;");
            actions.getChildren().add(row);
        }
        HBox total = new HBox(8, new Label("Total cost"), new Region());
        Label totalValue = new Label(String.valueOf(ek.totalCost()));
        font(totalValue, numberFont, FontWeight.BOLD, 26);
        HBox.setHgrow(total.getChildren().get(1), Priority.ALWAYS);
        total.getChildren().add(totalValue);
        total.setAlignment(Pos.BASELINE_LEFT);
        total.setPadding(new Insets(6, 0, 0, 0));

        Label affected = new Label("Affected assets: " + String.join(", ", ek.affectedAssets()));
        affected.setWrapText(true);
        affected.setMinHeight(Region.USE_PREF_SIZE);
        Region strip = new Region();
        strip.setMinWidth(4);
        strip.setMaxWidth(4);
        strip.setStyle("-fx-background-color: " + (ek.verified() ? OK : SEV_CRIT) + ";");
        Label verifiedText = new Label(ek.verified()
                ? "Verified: no protected target can be reached after the cut."
                : "Check failed: a protected target can still be reached.");
        verifiedText.setWrapText(true);
        verifiedText.setMinHeight(Region.USE_PREF_SIZE);
        HBox verified = new HBox(10, strip, verifiedText);
        verified.setPadding(new Insets(6, 0, 6, 0));
        Label how = muted(String.format(Locale.ROOT, "Run time (Edmonds-Karp): %.2f ms", ek.nanos() / 1e6));
        planBox.getChildren().addAll(actions, total, affected, verified, how);
    }

    // ---- shared helpers ---------------------------------------------------------------------


    /** Sets a control's font through an inline style so it wins over the inherited stylesheet font. */
    private static void font(javafx.scene.control.Control c, String family, FontWeight weight, double size) {
        String w = weight == FontWeight.BOLD ? "bold" : "normal";
        c.setStyle(c.getStyle() + "-fx-font-family: '" + family + "'; -fx-font-size: " + size + "px; -fx-font-weight: " + w + ";");
    }

    private static void font(javafx.scene.control.Control c, String family, double size) {
        font(c, family, FontWeight.NORMAL, size);
    }

    private static Label heading(String text) {
        Label l = new Label(text);
        font(l, bodyFont, FontWeight.BOLD, 15);
        return l;
    }

    private static Label muted(String text) {
        Label l = new Label(text);
        l.setTextFill(Color.web(MUTED));
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
            return SEV_CRIT;
        }
        if (score >= 60) {
            return SEV_HIGH;
        }
        if (score >= 30) {
            return SEV_MED;
        }
        return SEV_LOW;
    }

    private static Color textOn(int score) {
        return score >= 60 ? Color.WHITE : Color.web(INK);
    }

    private static HBox legend(boolean withCut) {
        HBox row1 = new HBox(18);
        row1.setAlignment(Pos.CENTER_LEFT);
        row1.getChildren().add(legendItem(SEV_CRIT, "Shortest attack path"));
        if (withCut) {
            row1.getChildren().add(legendItem(INK, "Cut: blocked link or isolated host"));
        }
        row1.getChildren().add(legendItem(TARGET, "Protected target"));
        row1.getChildren().add(legendItem("#ffffff; -fx-border-color: " + INK + "; -fx-border-width: 3", "Compromised host"));
        HBox row2 = new HBox(14, muted("Risk:"), legendItem(SEV_LOW, "Low"), legendItem(SEV_MED, "Medium"),
                legendItem(SEV_HIGH, "High"), legendItem(SEV_CRIT, "Critical"));
        row2.setAlignment(Pos.CENTER_LEFT);
        return new HBox(new VBox(5, row1, row2));
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
        private boolean hasUnreachable;
        private double[] nx = new double[0];
        private double[] ny = new double[0];

        GraphView(boolean showCut) {
            this.showCut = showCut;
            holder.setMinSize(260, 260);
            holder.setStyle("-fx-background-color: #fbfcfd; -fx-border-color: " + RULE + ";");
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

        /** Hops from the nearest compromised host (links read both ways); unreachable hosts go last. */
        private int[] layers(Topology topo) {
            int n = topo.size();
            int[] dist = new int[n];
            Arrays.fill(dist, -1);
            ArrayDeque<Integer> queue = new ArrayDeque<>();
            for (int s : model.sources()) {
                dist[s] = 0;
                queue.add(s);
            }
            while (!queue.isEmpty()) {
                int u = queue.poll();
                for (Link l : topo.links()) {
                    int v = l.from() == u ? l.to() : (l.to() == u ? l.from() : -1);
                    if (v >= 0 && dist[v] < 0) {
                        dist[v] = dist[u] + 1;
                        queue.add(v);
                    }
                }
            }
            int max = Arrays.stream(dist).max().orElse(0);
            boolean any = Arrays.stream(dist).anyMatch(d -> d < 0);
            for (int i = 0; i < n; i++) {
                if (dist[i] < 0) {
                    dist[i] = max + 1;
                }
            }
            hasUnreachable = any;
            return dist;
        }

        void redraw() {
            GraphicsContext g = canvas.getGraphicsContext2D();
            double w = canvas.getWidth();
            double h = canvas.getHeight();
            g.clearRect(0, 0, w, h);
            if (model == null || !model.isAnalysed()) {
                return;
            }
            Topology topo = model.topology();
            int n = topo.size();
            nx = new double[n];
            ny = new double[n];
            int[] layer = layers(topo);
            int layerCount = Arrays.stream(layer).max().orElse(0) + 1;
            double left = 70;
            double right = 70;
            double top = 52;
            double bottom = 22;
            List<List<Integer>> columns = new ArrayList<>();
            for (int c = 0; c < layerCount; c++) {
                columns.add(new ArrayList<>());
            }
            for (int i = 0; i < n; i++) {
                columns.get(layer[i]).add(i);
            }
            for (List<Integer> col : columns) {
                col.sort((a1, b1) -> {
                    Incident ia = model.incidentFor(topo.asset(a1).name());
                    Incident ib = model.incidentFor(topo.asset(b1).name());
                    int byRisk = Integer.compare(ib == null ? -1 : ib.riskScore(), ia == null ? -1 : ia.riskScore());
                    return byRisk != 0 ? byRisk : Integer.compare(a1, b1);
                });
            }
            g.setTextAlign(TextAlignment.CENTER);
            g.setFont(Font.font(bodyFont, FontWeight.NORMAL, 12));
            for (int c = 0; c < layerCount; c++) {
                double x = layerCount == 1 ? w / 2 : left + c * (w - left - right) / (layerCount - 1);
                List<Integer> col = columns.get(c);
                for (int j = 0; j < col.size(); j++) {
                    int i = col.get(j);
                    nx[i] = x;
                    ny[i] = top + (j + 1) * (h - top - bottom) / (col.size() + 1);
                }
                String caption = c == 0 ? "Compromised"
                        : (hasUnreachable && c == layerCount - 1) ? "Not reachable"
                        : c + (c == 1 ? " step away" : " steps away");
                g.setFill(Color.web(MUTED));
                g.fillText(caption, x, 24);
                g.setStroke(Color.web("#dfe3e8"));
                g.setLineWidth(1);
                g.strokeLine(x, 34, x, h - 14);
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

            g.setLineCap(StrokeLineCap.BUTT);
            g.setLineDashes((double[]) null);
            g.setStroke(Color.web("#c3ccd5"));
            g.setLineWidth(1.2);
            for (Link l : topo.links()) {
                g.strokeLine(nx[l.from()], ny[l.from()], nx[l.to()], ny[l.to()]);
            }
            g.setStroke(Color.web(SEV_CRIT));
            g.setLineWidth(4);
            for (Link l : topo.links()) {
                if (pathEdges.contains(edgeKey(n, l.from(), l.to()))) {
                    g.strokeLine(nx[l.from()], ny[l.from()], nx[l.to()], ny[l.to()]);
                }
            }
            g.setStroke(Color.web(INK));
            g.setLineWidth(4);
            g.setLineDashes(9, 7);
            for (int[] b : blocked) {
                g.strokeLine(nx[b[0]], ny[b[0]], nx[b[1]], ny[b[1]]);
            }
            g.setLineDashes((double[]) null);
            for (int[] b : blocked) {
                double mx = (nx[b[0]] + nx[b[1]]) / 2;
                double my = (ny[b[0]] + ny[b[1]]) / 2;
                g.setStroke(Color.web("#fbfcfd"));
                g.setLineWidth(8);
                g.strokeLine(mx - 8, my - 8, mx + 8, my + 8);
                g.strokeLine(mx - 8, my + 8, mx + 8, my - 8);
                g.setStroke(Color.web(INK));
                g.setLineWidth(3.5);
                g.strokeLine(mx - 8, my - 8, mx + 8, my + 8);
                g.strokeLine(mx - 8, my + 8, mx + 8, my - 8);
            }

            g.setTextAlign(TextAlignment.CENTER);
            for (int i = 0; i < n; i++) {
                String name = topo.asset(i).name();
                Incident inc = model.incidentFor(name);
                boolean isSelected = name.equals(selectedHost);
                double r = NODE_R;
                g.setFill(inc == null ? Color.web("#e3e7ec") : Color.web(levelColor(inc.riskScore())));
                g.fillOval(nx[i] - r, ny[i] - r, 2 * r, 2 * r);
                boolean source = model.sources().contains(i);
                boolean target = model.targets().contains(i);
                if (source || target) {
                    g.setStroke(Color.web(source ? INK : TARGET));
                    g.setLineWidth(5);
                    g.strokeOval(nx[i] - r, ny[i] - r, 2 * r, 2 * r);
                } else {
                    g.setStroke(Color.web("#8f9ba8"));
                    g.setLineWidth(1);
                    g.strokeOval(nx[i] - r, ny[i] - r, 2 * r, 2 * r);
                }
                if (isSelected) {
                    g.setStroke(Color.web(INK));
                    g.setLineWidth(1.5);
                    g.strokeOval(nx[i] - r - 6, ny[i] - r - 6, 2 * r + 12, 2 * r + 12);
                }
                if (isolated.contains(i)) {
                    g.setStroke(Color.web(INK));
                    g.setLineWidth(4);
                    g.setLineDashes(6, 5);
                    g.strokeOval(nx[i] - r - 9, ny[i] - r - 9, 2 * r + 18, 2 * r + 18);
                    g.setLineDashes((double[]) null);
                    g.strokeLine(nx[i] - r, ny[i] - r, nx[i] + r, ny[i] + r);
                    g.strokeLine(nx[i] - r, ny[i] + r, nx[i] + r, ny[i] - r);
                }
                if (inc != null) {
                    g.setFill(textOn(inc.riskScore()));
                    g.setFont(Font.font(numberFont, FontWeight.BOLD, 13));
                    g.fillText(String.valueOf(inc.riskScore()), nx[i], ny[i] + 5);
                }
                double ly = ny[i] + r + (isolated.contains(i) ? 23 : 15);
                g.setFont(Font.font(bodyFont, isSelected ? FontWeight.BOLD : FontWeight.NORMAL, 12));
                g.setStroke(Color.web("#fbfcfd"));
                g.setLineWidth(4);
                g.strokeText(name, nx[i], ly);
                g.setFill(Color.web(INK));
                g.fillText(name, nx[i], ly);
            }
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}