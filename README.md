# BreachPath

Enterprise breach analysis and containment optimisation, written in Java 17+.

BreachPath is a defensive tool. It takes a simulated enterprise network and a log of security
alerts, works out how an attacker could move from a compromised host to a protected target,
ranks the incidents by risk, and recommends the cheapest way to cut the attacker off. It runs as
a web application (Java REST API plus browser frontend), as a console report, and as a JavaFX
dashboard.

All data is synthetic. The results are experiments on that data, not proof of real-world protection.

## What it does

1. Loads a network of hosts and links, a log of hourly alert counts, known indicators of compromise
   (IOCs) and wildcard hunting patterns from the `data/` folder, or from files uploaded in the
   browser. Bad input is rejected with the file, line and column of the problem.
2. Finds the shortest attack path from each compromised host to each protected target.
3. Searches the evidence: IOC screening and prefix search, wildcard command patterns, and alert
   totals and peaks over a chosen time window.
4. Scores every host with an explainable risk score and keeps the incidents ordered by risk.
5. Summarises the score distribution (median, 75th and 90th percentile) with randomized selection.
6. Computes the cheapest containment with max flow / min cut, in two scenarios: compromised hosts
   stay online (A), or isolating the compromised host itself is allowed (B).
7. Checks each plan by removing the chosen links and hosts and confirming that no target is still
   reachable.
8. Benchmarks every technique against a plain baseline at three input sizes.
9. Exports the analysis as a single HTML report you can open in a browser or print to PDF.

## The seven techniques

Each technique solves a different part of the problem, and they feed one another. All of them are
implemented in this repository; the JDK collections are used only for plumbing and as test baselines.

| Technique | Syllabus unit | Where | Role |
|---|---|---|---|
| Max flow / min cut (Edmonds-Karp) | 5 | `graph/`, `engine/ContainmentPlanner` | cheapest hosts and links to isolate |
| Bloom filter | 6 (CO5) | `bloom/BloomFilter`, `engine/IocEngine` | fast "definitely absent / possibly present" screen of indicators |
| Randomized Quickselect | 6 (CO5) | `select/RandomizedSelect`, `ui/DashboardModel` | median and percentiles of incident risk without sorting |
| Prefix trie | 4 | `trie/Trie`, `engine/IocEngine` | exact confirmation of indicators, prefix search |
| Wildcard word dictionary | 4 | `trie/WordDictionary`, `engine/PatternEngine` | hunt with partially known commands (`.` = one character) |
| Segment tree | 3 | `segmenttree/`, `engine/EventTimeline` | alert totals and peaks over time windows |
| Red-black tree | 3 | `rbtree/`, `engine/IncidentIndex` | incidents ordered by (riskScore, incidentId) |

How they fit together: the segment tree turns the alert log into window totals and peaks. The
Bloom filter screens each indicator in the log; only "possibly present" answers reach the trie,
which confirms them exactly, and the tries also match command patterns. The risk scorer combines
those findings and keeps each host's incident in the red-black tree, so the highest-risk case is
always at hand and re-scoring is cheap. Randomized Quickselect reads the score distribution
without sorting it. The flow engine then calculates containment options from the isolation and
link costs in the data.

### Bloom filter (probabilistic component)

The filter holds every exact indicator. Sizing follows the standard formulas: for n indicators and
a target false-positive rate p (1%), it uses m = -n ln p / (ln 2)^2 bits and k = (m / n) ln 2 hash
functions, derived from two 64-bit hashes by double hashing.

- "Definitely absent" is certain: the filter has no false negatives.
- "Possibly present" is never trusted on its own. The trie always confirms it, so a false positive
  cannot flag a clean indicator. The answers of the engine are identical to a trie-only engine,
  which the tests check on 20,000 random probes.
- Prefix rules (`203.0.113.*`) are matched by the prefix trie, because a Bloom filter cannot answer
  prefix questions.
- Honest limit: against an in-memory trie the filter saves little or no time, because a miss in a
  trie is already cheap (see the benchmark conclusion). It pays off when the authoritative check is
  expensive, such as a database or remote feed, since about half of the lookups in the benchmark
  never reach it. The filter needs about 10 bits per indicator.

### Randomized Quickselect

Finds the k-th smallest value by partitioning around a random pivot and following only the side
that holds the target rank. Expected O(n) comparisons for any input (the random pivot, not the
data, decides the running time), against O(n log n) for sorting. It uses a three-way partition, so
many equal scores do not slow it down. It does not modify its input. The dashboard uses a fixed
seed, so the same data always gives the same numbers. The result shows the number of comparisons
used. It is the right tool for one or a few percentiles; for many queries on the same data, sort
once.

### Risk score

The score is capped at 100 and every point can be traced to a rule:

| Factor | Points |
|---|---|
| Peak alerts in one hour | 3 per alert, up to 30 |
| Alerts in the chosen window | 1 per 5 alerts, up to 20 |
| Known IOC hits | 20 each, up to 30 |
| Suspicious command patterns | 15 each, up to 20 |
| Can reach a protected target | 10 |
| Internet-facing and unpatched | 15 |
| Unpatched but internal | 5 |

Priority labels: 80 and above is Critical, 60 to 79 High, 30 to 59 Medium, below 30 Low.

### Containment

Each host is split into an "in" and an "out" node, joined by an edge whose capacity is the cost of
isolating that host. A link becomes an edge whose capacity is the cost of blocking it. A cut
through a host edge means "isolate this host", and a cut through a link edge means "block this
link". Targets can never be isolated. A link cost of 1,000,000 (the `INF` constant in
`ContainmentPlanner`) marks a link that must never be cut. If an uncuttable path reaches a target,
the plan reports that no finite-cost containment exists.

## Inputs, outputs, constraints and failure cases

**Inputs.** Five files in `data/` (or uploaded on the Data tab), plus the compromised hosts, the
protected targets and an hour window chosen by the user.

**Outputs.** Attack paths, a ranked incident list with the reasons for each score, score
percentiles, indicator screening results, wildcard matches, two containment plans with their
verification result, a what-if table, benchmark tables, and an HTML report.

**Constraints and assumptions.**

- Costs are whole numbers from 0 to 1,000,000. Alerts are counted per hour, hours 0 to 23.
- At most 500 assets per network. Request bodies are limited to 2 MB.
- Costs are the user's own estimates. A recommended cut is the cheapest under those costs only.
- The web server listens on 127.0.0.1 by default, so it is reachable only from your own computer.

**Failure cases and how they are handled.**

| Situation | Behaviour |
|---|---|
| Empty asset file, missing header row, wrong column count | rejected with file and line, nothing is loaded |
| Duplicate asset name, link to an unknown asset | rejected with the offending name |
| Non-numeric, negative or oversized cost; hour outside 0 to 23; negative alert count | rejected with file, line and column |
| Empty alert log, IOC list or pattern list | allowed; the analysis runs with no evidence from that source |
| Alert-log host that is not in the asset list | ignored and reported as a warning |
| Host that is both compromised and a target | rejected (HTTP 400) |
| No route from a compromised host to a target | reported as "unreachable", cost 0 |
| Uncuttable route to a target | plan marked infeasible with an explanation |
| Invalid upload | the previous data stays loaded |
| JSON error, unknown host, bad window | HTTP 400 with a message |
| Request without a JSON content type | HTTP 415 |
| Body over 2 MB | HTTP 413 |
| Analysis requested before any analysis exists | HTTP 409 |

## Data files

All files are in `data/`. Lines starting with `#` are comments.

| File | Columns or format |
|---|---|
| `assets.csv` | `name,type,isolationCost[,internetFacing,patched]` (the last two are optional and take true or false; a row without them is internal and patched) |
| `network_edges.csv` | `from,to,cost,bidirectional` |
| `security_events.csv` | `hour,host,eventType,count,indicator,command` (`-` means none; hour is 0 to 23) |
| `iocs.txt` | one exact indicator per line; a trailing `*` makes it a prefix rule |
| `patterns.txt` | one wildcard pattern per line; `.` matches exactly one character |

The CSV files need a header row. The sample data is synthetic and was written for this project.

## Requirements

- Java 17 or newer
- Maven (only needed to build with Maven and to run the JavaFX dashboard)

The web application, the console report and the tests need no libraries beyond the JDK (and JUnit
for the tests).

## Run

### Web application (REST API and browser frontend)

    mvn package
    java -cp target/breachpath-1.0.jar com.breachpath.web.WebApp

Then open http://127.0.0.1:8090/ in a browser. Optional arguments and settings (none is a secret):

    java -cp target/breachpath-1.0.jar com.breachpath.web.WebApp [dataDir] [port]
    BREACHPATH_DATA=data PORT=8090 BREACHPATH_HOST=127.0.0.1

The browser only displays results. Every algorithm runs in the Java backend. The tabs are:

- **Overview:** choose compromised hosts and targets and a time window, run the analysis, and see
  the incident ranking, score percentiles, cheapest containment costs, the network map and the
  attack paths.
- **Investigation:** all incidents with a plain explanation of each score, add evidence (re-scores
  the incident and moves it in the tree), close an incident, screen an indicator with the Bloom
  filter, search IOCs by prefix, and match wildcard patterns.
- **Containment:** the two scenarios side by side with the recommended actions, the verification
  result, and an editable link-cost panel (change a cost or mark a link as never to be cut and watch
  the plans update).
- **What-if:** treats every other host in turn as the only compromised one and shows the distance to
  the target and the cheapest containment in each scenario.
- **Data:** upload your own five files (validated before anything is replaced), reload the sample
  data, and download the HTML report.
- **Benchmarks:** runs the scaling study (quick or full) and shows each technique against its baseline.

### REST API

All responses are JSON. POST requests must send `Content-Type: application/json`.

| Method and path | Purpose |
|---|---|
| `GET /api/health` | loaded dataset summary and warnings |
| `GET /api/topology` | assets and links |
| `POST /api/analyse` | run the analysis; body `{"compromised":["WS-Alice"],"targets":["DB-PROD"],"fromHour":0,"toHour":23}` |
| `GET /api/result` | the current analysis (paths, incidents, percentiles, both plans, Bloom statistics) |
| `GET /api/incidents` | ranked incidents |
| `POST /api/incidents/evidence` | body `{"host":"WS-Bob","hour":10,"delta":40}` |
| `POST /api/incidents/close` | body `{"host":"WS-Bob"}` |
| `GET /api/ioc/screen?indicator=...` | Bloom filter answer plus exact confirmation |
| `GET /api/ioc/search?prefix=...` | IOC prefix search |
| `GET /api/patterns?pattern=p.wershell` | wildcard match (without `pattern`, all configured patterns) |
| `GET /api/whatif` | what-if sweep |
| `PUT /api/links/{index}` | change one link cost; body `{"cost":25}` (use 1000000 for "never cut") |
| `POST /api/links/reset` | restore the original link costs |
| `POST /api/data` | upload `assets`, `edges`, `events`, `iocs`, `patterns` as text fields |
| `POST /api/data/reset` | reload the sample data |
| `GET /api/benchmarks?profile=quick` | run the scaling benchmarks (`quick` or `full`) |
| `GET /api/benchmarks/last` | the most recent benchmark result |
| `GET /api/report` | the HTML report |

Examples:

    curl -s -X POST -H "Content-Type: application/json" \
      -d '{"compromised":["WS-Alice"],"targets":["DB-PROD"],"fromHour":0,"toHour":23}' \
      http://127.0.0.1:8080/api/analyse

    curl -s "http://127.0.0.1:8090/api/ioc/screen?indicator=185.220.101.7"
    curl -s "http://127.0.0.1:8090/api/ioc/screen?indicator=clean.example.org"

The first screening call answers `"bloom":"possibly present"` with `"exactConfirmed":true`. The
second answers `"bloom":"definitely absent"` and the exact check is skipped.

### Console report

    mvn package
    java -jar target/breachpath-1.0.jar
    java -jar target/breachpath-1.0.jar data WS-Alice DB-PROD benchmark

Arguments: `[dataDir] [compromisedHosts] [targets] [benchmark]`. Hosts may be comma separated,
for example `WS-Alice,WS-Bob`. The report includes the indicator screening table and the score
percentiles. With `benchmark` it also prints the performance evaluation and the scaling study
(about half a minute).

### Dashboard (JavaFX)

    mvn javafx:run

The desktop dashboard shows the incident ranking, containment plans, what-if table and a panel per
data structure. Compromised hosts and targets are chosen from drop-downs with tick boxes. The
Export report button saves the analysis as one HTML file.

### Without Maven

    mkdir -p out
    javac -d out $(find src/main -name "*.java" ! -name DashboardApp.java)
    cp -r src/main/resources/. out/
    java -cp out com.breachpath.ui.ConsoleApp
    java -cp out com.breachpath.ui.ConsoleApp data WS-Alice,WS-Bob DB-PROD,CLOUD-ADMIN benchmark
    java -cp out com.breachpath.web.WebApp

The JavaFX dashboard needs JavaFX, so use Maven for that.

## Tests

    mvn test

172 JUnit tests cover each data structure on its own (at least five tests per core technique, each
with a boundary case), the containment planner against a brute-force minimum cut, corner cases
(disconnected graphs, uncuttable paths, equal scores, empty patterns, repeated updates, bad input
files), the Bloom filter (no false negatives, measured false-positive rate against the target,
sizing formulas, invalid parameters), Randomized Quickselect (against sorting on random,
repeated, sorted and reversed data), Bloom screening against an exact-only reference, input
validation of every data file, the JSON layer, and the REST API on a real local server (routing,
status codes, upload validation, size limits). The dashboard logic lives in `ui/DashboardModel`,
which has no JavaFX code, so it can be tested without a window.

## Results

Example results from the benchmark run in a Linux container. Each time is the median of 5 runs after
one warm-up run, on seeded synthetic data. Absolute times on a laptop will differ; the ratios are
the point. The Benchmarks tab and `benchmark` console mode reproduce them.

| Technique | Baseline | Sizes | Result |
|---|---|---|---|
| Edmonds-Karp max flow | brute-force minimum cut (200 random graphs) | 100, 200, 400 nodes | 0 mismatches; 400 nodes and 2,396 edges in about 5 ms; brute force is limited to 22 edges |
| Randomized Quickselect | full sort, then index | 10,000 / 50,000 / 200,000 values | 2.7x, 12.1x, 13.2x faster; 1.1 to 3.2 comparisons per element |
| Bloom filter screen + trie | trie lookup only | 1,000 / 10,000 / 50,000 indicators | identical answers; false-positive rate 0.91% to 1.05% (target 1%); about 50% of lookups skip the trie; no speed-up in memory |
| Prefix trie | linear scan with `startsWith` | 5,000 / 20,000 / 50,000 words | 66x, 282x, 482x faster |
| Wildcard dictionary | naive scan | 2,000 / 10,000 / 25,000 words | 16x, 71x, 230x faster |
| Segment tree | naive range scan | 5,000 / 25,000 / 100,000 slots | 2.6x, 15x, 37x faster |
| Red-black tree | `java.util.TreeMap` | 5,000 / 20,000 / 50,000 keys | all invariants hold; similar speed, as expected |

When each technique helps: the trie, dictionary and segment tree pay off as the data grows and are
unnecessary for a handful of items (the sample alert log has 24 slots per host). Quickselect helps
when you need one or a few order statistics. The Bloom filter helps when the authoritative check is
costly, not when it is an in-memory lookup.

## Limitations

- The network, the alerts and the costs are synthetic. The recommended cuts are the cheapest under
  the costs in `data/`, and say nothing about a real network.
- Benchmark times are medians of 5 runs on one machine, so differences of a few percent are noise.
- Wildcard matching supports `.` only, and indicator matching is by exact string or prefix.
- Alerts are counted per hour (0 to 23), and the risk weights are simple, hand-chosen rules.
- The Bloom filter is sized once from the loaded indicator list. Adding many more indicators later
  raises its false-positive rate (the estimate is shown), though answers stay correct because every
  positive is confirmed.
- The web application keeps one shared analysis session in memory. It is a local analysis tool, has no
  user accounts, and is not meant to be exposed to a network.

## Project layout

    BreachPath/
    ├── pom.xml
    ├── data/                  assets, links, alert log, IOCs, patterns
    ├── docs/screenshots/      screenshots of the web application
    ├── src/main/java/com/breachpath/
    │   ├── model/             Asset, Link, Topology, SecurityEvent, Incident
    │   ├── graph/             flow network, Edmonds-Karp, min cut, brute-force check
    │   ├── bloom/             Bloom filter
    │   ├── select/            randomized Quickselect
    │   ├── trie/              prefix trie, wildcard word dictionary
    │   ├── segmenttree/       range sum and maximum with point updates
    │   ├── rbtree/            red-black tree
    │   ├── engine/            attack paths, risk scoring, containment, benchmarks
    │   ├── storage/           CSV and text loading and validation
    │   ├── web/               REST API server, service layer, JSON, application entry point
    │   └── ui/                console report and JavaFX dashboard
    ├── src/main/resources/    web frontend, stylesheet and bundled fonts
    └── src/test/java/com/breachpath/

## Screenshots

![Overview](docs/screenshots/overview.png)
![Investigation](docs/screenshots/investigation.png)
![Containment](docs/screenshots/containment.png)
![Benchmarks](docs/screenshots/benchmarks.png)

## Fonts

The application bundles Fira Sans and IBM Plex Mono, both under the SIL Open Font License 1.1. The
font files and their licences are in `src/main/resources/fonts/`.
