package com.breachpath.ui;

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
import javafx.scene.control.RadioButton;
import javafx.scene.control.Spinner;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * JavaFX dashboard: network graph (attack paths and containment cut), incident table,
 * hourly alert chart and containment comparison. Run with: mvn javafx:run
 */
public final class DashboardApp extends Application {
    private static final double NODE_R = 24;

    private DashboardModel model;
    private DashboardModel.Scenario scenario = DashboardModel.Scenario.NONE;

    private final Canvas canvas = new Canvas(640, 460);
    private final TableView<Incident> table = new TableView<>();
    private final TextArea reasonsArea = new TextArea();
    private final TextArea planArea = new TextArea();
    private final Label status = new Label();
    private final CategoryAxis hourAxis = new CategoryAxis();
    private final NumberAxis countAxis = new NumberAxis();
    private final BarChart<String, Number> chart = new BarChart<>(hourAxis, countAxis);

    private final TextField compromisedField = new TextField("WS-Alice");
    private final TextField targetField = new TextField("DB-PROD");
    private final Spinner<Integer> fromSpinner = new Spinner<>(0, 23, 0);
    private final Spinner<Integer> toSpinner = new Spinner<>(0, 23, 23);
    private final Spinner<Integer> hourSpinner = new Spinner<>(0, 23, 12);
    private final Spinner<Integer> deltaSpinner = new Spinner<>(1, 500, 30);

    private double[] nodeX = new double[0];
    private double[] nodeY = new double[0];

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

        BorderPane root = new BorderPane();
        root.setTop(buildControls());
        root.setCenter(buildCenter());
        root.setBottom(buildBottom());

        stage.setTitle("BreachPath - Breach Analysis and Containment");
        stage.setScene(new Scene(root, 1280, 860));
        stage.show();
        runAnalysis();
    }

    // ---- layout -----------------------------------------------------------------------------

    private HBox buildControls() {
        fromSpinner.setEditable(true);
        toSpinner.setEditable(true);
        fromSpinner.setPrefWidth(75);
        toSpinner.setPrefWidth(75);
        compromisedField.setPrefWidth(170);
        compromisedField.setPromptText("WS-Alice,WS-Bob");
        targetField.setPrefWidth(170);
        targetField.setPromptText("DB-PROD,CLOUD-ADMIN");
        Button run = new Button("Analyse / reset");
        run.setDefaultButton(true);
        run.setOnAction(e -> runAnalysis());
        status.setWrapText(true);
        HBox box = new HBox(8, new Label("Compromised:"), compromisedField, new Label("Targets:"), targetField,
                new Label("Hours from"), fromSpinner, new Label("to"), toSpinner, run, status);
        box.setAlignment(Pos.CENTER_LEFT);
        box.setPadding(new Insets(10));
        HBox.setHgrow(status, Priority.ALWAYS);
        return box;
    }

    private HBox buildCenter() {
        Pane holder = new Pane(canvas);
        holder.setMinSize(300, 300);
        canvas.widthProperty().bind(holder.widthProperty());
        canvas.heightProperty().bind(holder.heightProperty());
        canvas.widthProperty().addListener(o -> redraw());
        canvas.heightProperty().addListener(o -> redraw());
        canvas.setOnMouseClicked(e -> selectNodeAt(e.getX(), e.getY()));

        TableColumn<Incident, Integer> idCol = new TableColumn<>("Id");
        idCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().id()));
        idCol.setPrefWidth(40);
        TableColumn<Incident, String> hostCol = new TableColumn<>("Host");
        hostCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().host()));
        hostCol.setPrefWidth(110);
        TableColumn<Incident, Integer> riskCol = new TableColumn<>("Risk");
        riskCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().riskScore()));
        riskCol.setPrefWidth(55);
        TableColumn<Incident, String> whyCol = new TableColumn<>("Top reason");
        whyCol.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(
                c.getValue().reasons().isEmpty() ? "" : c.getValue().reasons().get(0)));
        whyCol.setPrefWidth(260);
        table.getColumns().add(idCol);
        table.getColumns().add(hostCol);
        table.getColumns().add(riskCol);
        table.getColumns().add(whyCol);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        table.getSelectionModel().selectedItemProperty().addListener((o, a, b) -> onSelection(b));

        reasonsArea.setEditable(false);
        reasonsArea.setWrapText(true);
        reasonsArea.setPrefRowCount(6);

        Button add = new Button("Add evidence");
        add.setOnAction(e -> addEvidence());
        hourSpinner.setEditable(true);
        deltaSpinner.setEditable(true);
        hourSpinner.setPrefWidth(75);
        deltaSpinner.setPrefWidth(85);
        Label hourLabel = new Label("Hour:");
        Label alertsLabel = new Label("Extra alerts:");
        hourLabel.setMinWidth(Label.USE_PREF_SIZE);
        alertsLabel.setMinWidth(Label.USE_PREF_SIZE);
        add.setMinWidth(Button.USE_PREF_SIZE);
        HBox evidence = new HBox(8, hourLabel, hourSpinner, alertsLabel, deltaSpinner, add);
        evidence.setAlignment(Pos.CENTER_LEFT);

        Label title = new Label("Incident queue (red-black tree, highest risk first)");
        title.setFont(Font.font(null, FontWeight.BOLD, 13));
        VBox right = new VBox(8, title, table, new Label("Why this score (select an incident, or click a node)"), reasonsArea, new Label("Simulate new evidence for the selected host:"), evidence);
        right.setPadding(new Insets(0, 10, 0, 10));
        right.setPrefWidth(500);
        VBox.setVgrow(table, Priority.ALWAYS);

        HBox center = new HBox(holder, right);
        HBox.setHgrow(holder, Priority.ALWAYS);
        return center;
    }

    private HBox buildBottom() {
        chart.setAnimated(false);
        chart.setLegendVisible(false);
        chart.setCategoryGap(2);
        hourAxis.setLabel("hour of day");
        countAxis.setLabel("alerts");
        chart.setPrefHeight(260);

        ToggleGroup group = new ToggleGroup();
        RadioButton none = new RadioButton("No containment");
        RadioButton strict = new RadioButton("Scenario A: compromised hosts stay online");
        RadioButton relaxed = new RadioButton("Scenario B: isolating compromised hosts allowed");
        none.setToggleGroup(group);
        strict.setToggleGroup(group);
        relaxed.setToggleGroup(group);
        none.setSelected(true);
        none.setOnAction(e -> setScenario(DashboardModel.Scenario.NONE));
        strict.setOnAction(e -> setScenario(DashboardModel.Scenario.STRICT));
        relaxed.setOnAction(e -> setScenario(DashboardModel.Scenario.RELAXED));

        planArea.setEditable(false);
        planArea.setFont(Font.font("Monospaced", 12));
        VBox plan = new VBox(6, new Label("Containment (max flow / min cut) - choose what to draw on the graph"),
                new VBox(4, none, strict, relaxed), planArea);
        VBox.setVgrow(planArea, Priority.ALWAYS);
        plan.setPadding(new Insets(0, 10, 10, 10));
        plan.setPrefWidth(660);

        HBox bottom = new HBox(10, chart, plan);
        bottom.setPadding(new Insets(0, 0, 0, 10));
        HBox.setHgrow(chart, Priority.ALWAYS);
        bottom.setPrefHeight(300);
        return bottom;
    }

    // ---- actions ----------------------------------------------------------------------------

    private void runAnalysis() {
        try {
            model.analyse(compromisedField.getText(), targetField.getText(),
                    fromSpinner.getValue(), toSpinner.getValue());
            status.setStyle("-fx-text-fill: #2e7d32;");
            status.setText("Analysed. Tree balanced: " + model.isBalanced());
            refresh(null);
        } catch (IllegalArgumentException ex) {
            status.setStyle("-fx-text-fill: #c62828;");
            status.setText("Error: " + ex.getMessage());
        }
    }

    private void addEvidence() {
        Incident sel = table.getSelectionModel().getSelectedItem();
        if (sel == null) {
            status.setStyle("-fx-text-fill: #c62828;");
            status.setText("Select an incident first.");
            return;
        }
        try {
            Incident before = sel;
            Incident after = model.addEvidence(sel.host(), hourSpinner.getValue(), deltaSpinner.getValue());
            status.setStyle("-fx-text-fill: #2e7d32;");
            status.setText(String.format("%s: risk %d -> %d (tree balanced: %s)", sel.host(),
                    before.riskScore(), after.riskScore(), model.isBalanced()));
            refresh(sel.host());
        } catch (IllegalArgumentException ex) {
            status.setStyle("-fx-text-fill: #c62828;");
            status.setText("Error: " + ex.getMessage());
        }
    }

    private void setScenario(DashboardModel.Scenario s) {
        scenario = s;
        redraw();
    }

    private void refresh(String keepHost) {
        String host = keepHost;
        if (host == null) {
            Incident sel = table.getSelectionModel().getSelectedItem();
            host = sel == null ? null : sel.host();
        }
        List<Incident> ranked = model.ranked();
        table.setItems(FXCollections.observableArrayList(ranked));
        int pick = 0;
        for (int i = 0; i < ranked.size(); i++) {
            if (ranked.get(i).host().equals(host)) {
                pick = i;
            }
        }
        if (!ranked.isEmpty()) {
            table.getSelectionModel().select(pick);
        }
        planArea.setText(planReport());
        onSelection(table.getSelectionModel().getSelectedItem());
    }

    private void onSelection(Incident inc) {
        if (inc == null) {
            reasonsArea.clear();
            chart.getData().clear();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(inc.host()).append("  |  risk ").append(inc.riskScore()).append("\n");
            for (String r : inc.reasons()) {
                sb.append(" - ").append(r).append("\n");
            }
            reasonsArea.setText(sb.toString());
            updateChart(inc.host());
        }
        redraw();
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
        chart.setTitle(String.format("%s: alerts per hour (window %d-%d: total %d, peak %d)", host,
                model.from(), model.to(), model.windowTotal(host), model.windowPeak(host)));
    }

    private String planReport() {
        StringBuilder sb = new StringBuilder();
        appendPlan(sb, "Scenario A (compromised hosts stay online)", DashboardModel.Scenario.STRICT);
        sb.append("\n");
        appendPlan(sb, "Scenario B (isolating compromised hosts allowed)", DashboardModel.Scenario.RELAXED);
        return sb.toString();
    }

    private void appendPlan(StringBuilder sb, String title, DashboardModel.Scenario s) {
        ContainmentPlan ek = model.plan(s, false);
        ContainmentPlan ff = model.plan(s, true);
        sb.append(title).append("\n");
        if (!ek.feasible()) {
            sb.append("  No finite-cost containment exists (an uncuttable path reaches a target).\n");
            return;
        }
        for (ContainmentPlan.Action a : ek.actions()) {
            sb.append(String.format("  - %-34s cost %d%n", a.description(), a.cost()));
        }
        sb.append(String.format("  Total cost %d | verified: %s | affected: %s%n", ek.totalCost(), ek.verified(),
                ek.affectedAssets()));
        sb.append(String.format("  %s %.3f ms  vs  %s %.3f ms  (costs agree: %s)%n", ek.algorithm(),
                ek.nanos() / 1e6, ff.algorithm(), ff.nanos() / 1e6, ek.totalCost() == ff.totalCost()));
    }

    private void selectNodeAt(double x, double y) {
        for (int i = 0; i < nodeX.length; i++) {
            if (Math.hypot(x - nodeX[i], y - nodeY[i]) <= NODE_R + 4) {
                String host = model.topology().asset(i).name();
                for (Incident inc : table.getItems()) {
                    if (inc.host().equals(host)) {
                        table.getSelectionModel().select(inc);
                        return;
                    }
                }
                status.setStyle("-fx-text-fill: #555555;");
                status.setText(host + " has no incident in the queue.");
                return;
            }
        }
    }

    // ---- drawing ----------------------------------------------------------------------------

    private void redraw() {
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
        nodeX = new double[n];
        nodeY = new double[n];
        double radius = Math.max(60, Math.min(w, h) / 2 - 70);
        for (int i = 0; i < n; i++) {
            double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
            nodeX[i] = w / 2 + radius * Math.cos(angle);
            nodeY[i] = h / 2 + 8 + radius * Math.sin(angle);
        }

        Set<Long> pathEdges = new HashSet<>();
        for (List<Integer> p : model.attackPaths()) {
            for (int i = 0; i + 1 < p.size(); i++) {
                pathEdges.add(edgeKey(n, p.get(i), p.get(i + 1)));
            }
        }
        ContainmentPlan plan = model.plan(scenario, false);
        List<int[]> blocked = model.blockedLinks(plan);
        Set<Integer> isolated = model.isolatedHosts(plan);

        g.setLineCap(StrokeLineCap.ROUND);
        g.setLineDashes((double[]) null);
        g.setStroke(Color.web("#b0b0b0"));
        g.setLineWidth(1.5);
        for (Link l : topo.links()) {
            g.strokeLine(nodeX[l.from()], nodeY[l.from()], nodeX[l.to()], nodeY[l.to()]);
        }
        g.setStroke(Color.web("#e53935"));
        g.setLineWidth(4);
        for (Link l : topo.links()) {
            if (pathEdges.contains(edgeKey(n, l.from(), l.to()))) {
                g.strokeLine(nodeX[l.from()], nodeY[l.from()], nodeX[l.to()], nodeY[l.to()]);
            }
        }
        g.setStroke(Color.web("#fb8c00"));
        g.setLineWidth(5);
        g.setLineDashes(10, 8);
        for (int[] b : blocked) {
            g.strokeLine(nodeX[b[0]], nodeY[b[0]], nodeX[b[1]], nodeY[b[1]]);
        }
        g.setLineDashes((double[]) null);
        g.setLineWidth(4);
        for (int[] b : blocked) {
            double mx = (nodeX[b[0]] + nodeX[b[1]]) / 2;
            double my = (nodeY[b[0]] + nodeY[b[1]]) / 2;
            g.strokeLine(mx - 8, my - 8, mx + 8, my + 8);
            g.strokeLine(mx - 8, my + 8, mx + 8, my - 8);
        }

        Incident selected = table.getSelectionModel().getSelectedItem();
        g.setTextAlign(TextAlignment.CENTER);
        for (int i = 0; i < n; i++) {
            String name = topo.asset(i).name();
            Incident inc = model.incidentFor(name);
            boolean isSelected = selected != null && selected.host().equals(name);
            double r = isSelected ? NODE_R + 4 : NODE_R;
            g.setFill(inc == null ? Color.web("#cfd8dc") : Color.hsb(120 * (1 - inc.riskScore() / 100.0), 0.65, 0.95));
            g.fillOval(nodeX[i] - r, nodeY[i] - r, 2 * r, 2 * r);
            Color ring = Color.web("#616161");
            double ringWidth = 1.5;
            if (model.sources().contains(i)) {
                ring = Color.web("#b71c1c");
                ringWidth = 4;
            } else if (model.targets().contains(i)) {
                ring = Color.web("#0d47a1");
                ringWidth = 4;
            }
            g.setStroke(ring);
            g.setLineWidth(ringWidth);
            g.strokeOval(nodeX[i] - r, nodeY[i] - r, 2 * r, 2 * r);
            if (isolated.contains(i)) {
                g.setStroke(Color.web("#fb8c00"));
                g.setLineWidth(4);
                g.strokeOval(nodeX[i] - r - 6, nodeY[i] - r - 6, 2 * r + 12, 2 * r + 12);
                g.strokeLine(nodeX[i] - r, nodeY[i] - r, nodeX[i] + r, nodeY[i] + r);
                g.strokeLine(nodeX[i] - r, nodeY[i] + r, nodeX[i] + r, nodeY[i] - r);
            }
            g.setFill(Color.BLACK);
            g.setFont(Font.font(null, FontWeight.BOLD, 12));
            if (inc != null) {
                g.fillText(String.valueOf(inc.riskScore()), nodeX[i], nodeY[i] + 4);
            }
            g.setFont(Font.font(null, FontWeight.NORMAL, 12));
            g.fillText(name, nodeX[i], nodeY[i] + r + 16);
        }

        g.setTextAlign(TextAlignment.LEFT);
        g.setFont(Font.font(null, FontWeight.NORMAL, 12));
        legend(g, 12, 18, Color.web("#e53935"), "red line = shortest attack path");
        legend(g, 12, 36, Color.web("#fb8c00"), "orange dashed = blocked link, orange ring = isolated host");
        legend(g, 12, 54, Color.web("#b71c1c"), "red ring = compromised host");
        legend(g, 12, 72, Color.web("#0d47a1"), "blue ring = protected target");
        g.setFill(Color.web("#424242"));
        g.fillText("node fill = risk score (green low, red high). Click a node to select it.", 12, h - 10);
    }

    private static void legend(GraphicsContext g, double x, double y, Color c, String text) {
        g.setFill(c);
        g.fillRect(x, y - 10, 14, 10);
        g.setFill(Color.web("#424242"));
        g.fillText(text, x + 20, y);
    }

    private static long edgeKey(int n, int a, int b) {
        return (long) Math.min(a, b) * n + Math.max(a, b);
    }

    public static void main(String[] args) {
        launch(args);
    }
}