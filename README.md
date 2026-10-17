# BreachPath

Enterprise breach analysis and containment optimisation (Java 17+, console first).

Five concepts, each solving a different part of the problem:

| Concept | Where | Role |
|---|---|---|
| Max flow / min cut (Edmonds-Karp, Ford-Fulkerson) | `graph/`, `engine/ContainmentPlanner` | cheapest hosts/links to isolate |
| Prefix trie | `trie/Trie`, `engine/IocEngine` | indicator-of-compromise search |
| Wildcard word dictionary | `trie/WordDictionary`, `engine/PatternEngine` | hunt with partially known commands (`.` = one char) |
| Segment tree | `segmenttree/`, `engine/EventTimeline` | alert totals / peaks over time windows |
| Red-black tree | `rbtree/`, `engine/IncidentIndex` | incidents ordered by (riskScore, incidentId) |

## Run without Maven

    mkdir -p out
    javac -d out $(find src/main -name "*.java")
    java -cp out com.breachpath.ui.ConsoleApp
    java -cp out com.breachpath.ui.ConsoleApp data WS-Alice,WS-Bob DB-PROD,CLOUD-ADMIN benchmark

## Run with Maven

    mvn test
    mvn package
    java -jar target/breachpath-1.0.jar
    java -jar target/breachpath-1.0.jar data WS-Alice DB-PROD benchmark

Arguments: `[dataDir] [compromisedHosts] [targets] [benchmark]` (hosts may be comma separated).

Results are experiments on synthetic data, not proof of real-world protection.
