# Graph databases

A worker can read a Memgraph graph database with any stock Neo4j or Memgraph driver. It connects to its sidecar at a `bolt://` (or `neo4j://`) address on its own loopback, signs in with the catalog entry's name and a fixed placeholder, and runs Cypher as usual. The worker never holds the database's login: the broker signs in to the database for it, and lets only queries that read the graph through. One sidecar port serves every graph database the pool is granted, so adding one is a catalog entry and a login in Vault, with no change to the worker.

## Connect from a worker

| Setting | Value |
|---|---|
| URI | `bolt://127.0.0.1:<port>` or `neo4j://127.0.0.1:<port>`, the pool's Bolt port (17687 in the examples here) |
| User | The catalog entry's name (`app-graph` in the examples here); it picks the database |
| Password | The port's placeholder (`gatehouse-relay-placeholder` in the examples here) |
| Encryption | None. The sidecar is on loopback; it reaches the broker over TLS. |

```python
from neo4j import GraphDatabase

with GraphDatabase.driver("neo4j://127.0.0.1:17687", auth=("app-graph", "gatehouse-relay-placeholder")) as driver:
    records, _, _ = driver.execute_query("MATCH (n:Person) RETURN n.name AS name", routing_="r")
```

`execute_query`, `execute_read`, auto-commit `session.run` and explicit read transactions all work. `neo4j://` works because the broker answers the driver's routing request with the sidecar's own address for every role. Gatehouse speaks Bolt 5.2 and 4.3, the versions Memgraph 3 accepts that current drivers offer.

## What runs

A query runs only when everything it does reads the graph. Before each query the broker asks the database to plan it (`EXPLAIN`) and checks every step of the plan against a list of steps that only read: scans, expands, path searches, filters, projections, aggregation, ordering and unions. A plan with any other step, such as `CreateNode`, `SetProperty`, `Delete` or `Merge`, is refused before the query reaches the database, with the step named in the refusal.

| Kind of query | What happens |
|---|---|
| `MATCH`, `RETURN`, `WITH`, `UNWIND`, `OPTIONAL MATCH`, path searches | Runs |
| `CREATE`, `MERGE`, `SET`, `REMOVE`, `DELETE`, `LOAD CSV` | Refused; the session stays open |
| A procedure (`CALL module.name`) | Refused unless the entry's `procedures` lists it |
| A module function (`module.name(...)`) | Refused unless the entry's `functions` lists it. Built-in functions such as `count`, `toUpper` or `date` run. |
| Index, constraint, user, trigger, snapshot and other administrative queries | Not run: the database cannot plan them, so its own error comes back |
| Any other query the database cannot plan | Not run; the database's own error, unchanged |

Procedures and functions are refused by default because a module can write, read files on the database server or reach the network, and none of that shows in a plan. List one only when you know it only reads, for example `schema.node_type_properties`.

As a second guard, every query runs inside a read transaction that the broker rolls back: an auto-commit query runs in one opened for it, and an explicit transaction's `COMMIT` is answered as a success and rolled back. A write that slipped past the plan check would still not be kept, apart from the few Memgraph operations that commit on their own, which the plan check refuses.

## Add a graph database

1. Create a login on the database for Gatehouse. Memgraph's Community edition has no read-only role, so Gatehouse does not rely on the login's privileges; give it the least the edition allows.
2. Write the login to a Vault key-value version 2 secret, fields `username` and `password`, and grant the broker read on it in the same change as the entry. The password must be printable ASCII.
3. Add the catalog entry:

```yaml
entries:
  - name: app-graph                     # the user name workers sign in with
    kind: memgraph
    host: memgraph.graphs.svc.cluster.local
    pools: [cursor-agents]
    memgraph:
      login: {mount: gatehouse, path: vendors/memgraph-app}
      serverName: graph.example.com     # the name on the server's certificate, when it is not the host
      procedures: [schema.node_type_properties]
      functions: [date.add]
```

| Field | Meaning |
|---|---|
| `port` | 7687 by default |
| `memgraph.login` | The Vault secret holding the broker's login. Never sent to a worker. |
| `memgraph.access` | `read`, the default and the only value accepted |
| `memgraph.sslmode` | `verify-full`, the default. `disable` is accepted only in a test deployment that allows plaintext databases, and only for a cluster-local host. |
| `memgraph.ca`, `memgraph.serverName` | As for a `postgres` entry: the only trust for the server's certificate, and the name it must carry |
| `memgraph.maxConns` | This database's connection budget across the broker, 1 to 100000; unset uses the broker's default |
| `memgraph.procedures`, `memgraph.functions` | The procedures and module functions a query may use, as `module.name` |

`tier`, `requires` and pool grants work as for every other entry.

The pool's worker template needs nothing new for it. Its sidecar has one routed Bolt port, which forwards any well-formed user name and leaves the decision to the broker's catalog:

```json
"boltListeners": [{
  "listen": "127.0.0.1:17687",
  "routes": "broker",
  "placeholder": "gatehouse-relay-placeholder",
  "upstream": {"address": "gatehouse.gatehouse.svc:15443", "serverName": "gatehouse.gatehouse.svc", "caFile": "/ca/ca.crt", "proofFile": "/proof/token", "audience": "gatehouse"}
}]
```

`entries`, a list of entry names, may replace `routes` to fix the port's route table. `upstream` is the same as a PostgreSQL binding's: Bolt arrives on the broker's database listener, which tells the two protocols apart from the first bytes. A shared proxy does not serve Bolt yet; a pool that needs a graph database runs a sidecar.

## How a session is checked

The sidecar checks everything the worker controls first: that the connection comes from the worker, a Bolt version both sides speak, the placeholder, and that the user name is a well-formed entry name (or, with `entries`, a listed one). Only then does it read the worker's identity proof and sign in to the broker with it, naming the catalog entry. The broker refuses a name its catalog does not grant the pool. The broker admits the session exactly as it admits a PostgreSQL session: the worker's identity, its pool's grant, the entry's tier and groups, the per-worker and per-database budgets, and a recheck while the session is open that ends it when access is withdrawn or the worker's deadline passes. Then it reads the login from Vault and signs in to the database. Any failure refuses the session; nothing falls back to a weaker path.

A driver that tries to sign in again on an open connection (`LOGON` after `LOGOFF`) is refused and the connection closes; drivers open a new connection instead.

## Refusals

Gatehouse's refusals arrive as Bolt failures with a code starting `Gatehouse.`. A driver retries codes whose second part is `TransientError`.

| Code | Message | Fix |
|---|---|---|
| `Gatehouse.ClientError.Statement.AccessMode` | this database is read-only; only queries that read the graph run here (refused: ...) | Read instead; ask for a procedure or function to be listed if it only reads |
| `Gatehouse.ClientError.Security.Unauthorized` | wrong placeholder password for this port | Use the port's placeholder |
| `Gatehouse.ClientError.Security.Unauthorized` | this user name is not a Gatehouse catalog entry for your pool | Use the entry's name as the user |
| `Gatehouse.ClientError.Security.Unauthorized` | Gatehouse could not verify this worker | Retry; tell the Gatehouse operators if it persists |
| `Gatehouse.TransientError.Security.NotVerified` | Gatehouse could not verify this worker | The sidecar could not read its identity proof; retry, and tell the Gatehouse operators if it persists |
| `Gatehouse.ClientError.Security.Forbidden` | this session's person is not authorized for this database (...) | Request the group, or use a pool with a person behind it |
| `Gatehouse.ClientError.Database.DatabaseNotFound` | this database isn't in the Gatehouse catalog for your pool | Add the entry or the grant |
| `Gatehouse.TransientError.General.SessionCap` | this worker reached its session cap | Close idle sessions |
| `Gatehouse.TransientError.General.DatabaseBudget` | the database's Gatehouse connection budget is full; retry shortly | Retry shortly |
| `Gatehouse.TransientError.General.Busy` | Gatehouse is at capacity; retry shortly | Retry shortly |
| `Gatehouse.TransientError.General.CredentialUnavailable` | Gatehouse could not get a database credential; retry shortly | Retry; tell the Gatehouse operators if it persists |
| `Gatehouse.TransientError.General.DatabaseUnavailable` | Gatehouse could not reach the database; retry | Retry; tell the Gatehouse operators if it persists |
| `Gatehouse.TransientError.General.Unavailable` | cannot reach Gatehouse | Retry; tell the Gatehouse operators if it persists |
| `Gatehouse.TransientError.General.SessionEnded` | Gatehouse ended the session (deadline or revocation) | Reconnect; a worker past its deadline is not admitted again |
| `Gatehouse.ClientError.Request.Invalid` | Gatehouse could not follow this request | Use a stock driver; tell the Gatehouse operators the pool and time |

Errors from the database itself, such as a syntax error, pass through unchanged.

## Audit

Each session writes a `bolt.session` row when it opens and when it closes, with the pool, the worker, the entry and how many queries were refused. Each refused query writes a `bolt.query` row naming the plan step, function or procedure that was refused. Query text and results are never recorded.

## Limits

| Limit | Default | Setting |
|---|---|---|
| One Bolt message, either direction | 64 MiB | `AGENT_VAULT_BOLT_MAX_MESSAGE_BYTES` on the broker |
| Connections to one database | The broker's per-database default | `memgraph.maxConns` |
| One query's run time | Memgraph's own query timeout | Memgraph's `--query-execution-timeout-sec` |

## Test against a real Memgraph

The `realmemgraph` tests run the broker, and the sidecar in front of it, against a disposable Memgraph serving Bolt over TLS:

```sh
AV_TEST_MEMGRAPH_ADDR=127.0.0.1:7687 \
AV_TEST_MEMGRAPH_SERVER_NAME=memgraph.test \
AV_TEST_MEMGRAPH_CA_FILE=./memgraph-cert.pem \
AV_TEST_MEMGRAPH_USER=gatehouse_reader \
AV_TEST_MEMGRAPH_PASSWORD=<the test login's password> \
AV_TEST_BOLT_DRIVER_CHECK="python3 ./driver_check.py" \
go test -tags realmemgraph -run TestRealMemgraph ./internal/pgproxy/
```

The database needs a few `Person` nodes and one `KNOWS` relationship. `AV_TEST_BOLT_DRIVER_CHECK` is optional: a command given the address to test as its last argument, and, for the sidecar, the user and placeholder before it, that runs a stock driver and exits 0 when every check passes.
