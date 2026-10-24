# BreachPath

Enterprise breach analysis and containment optimisation, written in Java 17+.

BreachPath is a defensive tool. It takes a simulated enterprise network and a log of security
alerts, works out how an attacker could move from a compromised host to a protected target,
ranks the incidents by risk, and recommends the cheapest way to cut the attacker off. It runs as
a console report and as a JavaFX dashboard.

All data is synthetic. The results are experiments on that data, not proof of real-world protection.

## What it does

1. Loads a network of hosts and links, a log of hourly alert counts, known indicators of compromise
   (IOCs) and wildcard hunting patterns from the `data/` folder.
2. Finds the shortest attack path from each compromised host to each protected target.
3. Searches the evidence: IOC prefix search, wildcard command patterns, and alert totals and peaks
   over a chosen time window.
4. Scores every host with an explainable risk score and keeps the incidents ordered by risk.
5. Computes the cheapest containment with max flow / min cut, in two scenarios: compromised hosts
   stay online (A), or isolating the compromised host itself is allowed (B).
6. Checks each plan by removing the chosen links and hosts and confirming that no target is still
   reachable.
7. Benchmarks every structure against a plain reference implementation.

## The five concepts

Each concept solves a different part of the problem, and they feed one another.

| Concept | Where | Role |
|---|---|---|
| Max flow / min cut (Edmonds-Karp) | `graph/`, `engine/ContainmentPlanner` | cheapest hosts and links to isolate |
| Prefix trie | `trie/Trie`, `engine/IocEngine` | indicator-of-compromise search |
| Wildcard word dictionary | `trie/WordDictionary`, `engine/PatternEngine` | hunt with partially known commands (`.` = one character) |
| Segment tree | `segmenttree/`, `engine/EventTimeline` | alert totals and peaks over time windows |
| Red-black tree | `rbtree/`, `engine/IncidentIndex` | incidents ordered by (riskScore, incidentId) |

How they fit together: the segment tree turns the alert log into window totals and peaks. The
tries match indicators and command patterns against the log. The risk scorer combines those
findings and keeps each host's incident in the red-black tree, so the highest-risk case is always
at hand and re-scoring is cheap. The flow engine then calculates containment options from the
isolation and link costs in the data.

### Risk score

The score is capped at 100 and every point can be traced to a rule:

| Factor | Points |
|---|---|
| Peak alerts in one hour | 3 per alert, up to 30 |
| Alerts in the chosen window | 1 per 5 alerts, up to 20 |
| Known IOC hits | 20 each, up to 30 |
| Suspicious command patterns | 15 each, up to 20 |
| Can reach a protected target | 10 |

Priority labels: 80 and above is Critical, 60 to 79 High, 30 to 59 Medium, below 30 Low.

### Containment

Each host is split into an "in" and an "out" node, joined by an edge whose capacity is the cost of
isolating that host. A link becomes an edge whose capacity is the cost of blocking it. A cut
through a host edge means "isolate this host", and a cut through a link edge means "block this
link". Targets can never be isolated. A link cost of 1,000,000 (the `INF` constant in
`ContainmentPlanner`) marks a link that must never be cut. If an uncuttable path reaches a target,
the plan reports that no finite-cost containment exists.

## Data files

All files are in `data/`. Lines starting with `#` are comments.

| File | Columns or format |
|---|---|
| `assets.csv` | `name,type,isolationCost` |
| `network_edges.csv` | `from,to,cost,bidirectional` |
| `security_events.csv` | `hour,host,eventType,count,indicator,command` (`-` means none; hour is 0 to 23) |
| `iocs.txt` | one exact indicator per line; a trailing `*` makes it a prefix rule |
| `patterns.txt` | one wildcard pattern per line; `.` matches exactly one character |

## Requirements

- Java 17 or newer
- Maven (only needed to build with Maven and to run the dashboard)

## Run

### Dashboard (JavaFX)

    mvn javafx:run

Compromised hosts and targets are chosen from drop-downs with tick boxes, so several can be picked at
once. Hover over a host on the map to see its type, isolation cost, risk and alert count. The
dashboard has five tabs:

- **Overview:** the network map laid out by distance from the compromised host, the highest-risk
  incidents, and an alert chart for the selected host.
- **Investigation:** all incidents, a plain explanation of the selected score, wildcard pattern
  hits, IOC prefix search, and two actions on the selected incident: add evidence (re-scores it and
  moves it in the tree) or close it (removes it from the tree).
- **Containment:** the two scenarios side by side, with the cut drawn on the map, the recommended
  actions, and the verification result.
- **Under the hood:** one panel per concept so each can be seen working. The cut costs that add up
  to the max flow, the indicators that still match after each character typed into the trie, the
  matches for a wildcard pattern, the stored segment-tree ranges combined for a window query, and
  the incident red-black tree drawn with its red and black nodes.
- **Benchmarks:** a summary of the five concepts with their correctness checks and timings, with
  the full output underneath.

### Console report

    mvn package
    java -jar target/breachpath-1.0.jar
    java -jar target/breachpath-1.0.jar data WS-Alice DB-PROD benchmark

Arguments: `[dataDir] [compromisedHosts] [targets] [benchmark]`. Hosts may be comma separated,
for example `WS-Alice,WS-Bob`.

### Without Maven

    mkdir -p out
    javac -d out $(find src/main -name "*.java")
    java -cp out com.breachpath.ui.ConsoleApp
    java -cp out com.breachpath.ui.ConsoleApp data WS-Alice,WS-Bob DB-PROD,CLOUD-ADMIN benchmark

The dashboard needs JavaFX, so use Maven for that.

## Tests

    mvn test

79 JUnit tests cover each data structure on its own, the containment planner against a
brute-force minimum cut, corner cases (disconnected graphs, uncuttable paths, equal scores, empty
patterns, repeated updates, bad input files) and the logic behind the dashboard, including the read-only tree views. The dashboard
logic lives in `ui/DashboardModel`, which has no JavaFX code, so it can be tested without a window.

## Results

An example run on the author's laptop (single run on generated data; timings change from run to
run, so use the Benchmarks tab to produce your own):

| Concept | Correctness check | Result |
|---|---|---|
| Max flow / min cut | matches brute force on 200 random graphs, 0 mismatches | Edmonds-Karp on 400 nodes and 2,396 edges: 2.47 ms |
| Prefix trie | same results as a linear scan | 3.03 ms vs 247.22 ms (about 82 times faster) |
| Wildcard dictionary | same matches as a naive scan | 2.53 ms vs 92.47 ms (about 37 times faster) |
| Segment tree | same answers as a naive scan | 14.09 ms vs 1038.07 ms (about 74 times faster) |
| Red-black tree | invariants hold and contents match `TreeMap` | 100,000 inserts and 50,000 removals in about 93 ms, height 20 (log2 n = 16.6) |

## Limitations

- The network, the alerts and the costs are synthetic. The recommended cuts are the cheapest under
  the costs in `data/`, and say nothing about a real network.
- Each benchmark is a single run without JVM warm-up, so small differences are noise.
- Wildcard matching supports `.` only, and indicator matching is by exact string or prefix.
- Alerts are counted per hour (0 to 23), and the risk weights are simple, hand-chosen rules.

## Project layout

    BreachPath/
    ├── pom.xml
    ├── data/                  assets, links, alert log, IOCs, patterns
    ├── src/main/java/com/breachpath/
    │   ├── model/             Asset, Link, Topology, SecurityEvent, Incident
    │   ├── graph/             flow network, Edmonds-Karp, min cut, brute-force check
    │   ├── trie/              prefix trie, wildcard word dictionary
    │   ├── segmenttree/       range sum and maximum with point updates
    │   ├── rbtree/            red-black tree
    │   ├── engine/            attack paths, risk scoring, containment, benchmarks
    │   ├── storage/           CSV and text loading
    │   └── ui/                console report and JavaFX dashboard
    ├── src/main/resources/    stylesheet and bundled fonts
    └── src/test/java/com/breachpath/

## Screenshots

![Overview](docs/screenshots/overview.png)
![Investigation](docs/screenshots/investigation.png)
![Containment](docs/screenshots/containment.png)
![Benchmarks](docs/screenshots/benchmarks.png)

## Fonts

The dashboard bundles Fira Sans and IBM Plex Mono, both under the SIL Open Font License 1.1. The
font files and their licences are in `src/main/resources/fonts/`.