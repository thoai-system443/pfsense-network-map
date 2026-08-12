# pfSense Network Map

Reads a pfSense `config.xml` backup and answers the question a rule table cannot:
**who can actually reach what, on which port, and where it gets stopped.**

Load several firewalls at once to follow the whole path a packet has to take.
Runs entirely offline and never calls out to the internet.

---

## Running it

Two independent stacks, each with its own `docker-compose.yml`:

```bash
cd backend && cp .env.example .env && docker compose up -d --build
```

```bash
cd frontend && cp .env.example .env && docker compose up -d --build
```

Open <http://localhost:8011>. The backend is on `:8010`.

To change a port or the backend address, edit `.env` and run `docker compose up -d`
— **no rebuild needed**, `API_URL` is read when the container starts.

> `docker compose restart` does **not** reload environment variables. Always use `up -d`.

## Loading data

On the first page, pick the `config.xml` of your first firewall. If the network has
more than one, pick the rest as well — they go into the same workspace and get
analysed as one system. Click **Open the map** when done.

**Read the warning list first.** The parser reports every field it does not
recognise instead of skipping it silently. An empty list means it understood the
whole file; a non-empty one means the results may be incomplete, and the warnings
say exactly where.

## Five screens

| | Answers |
|---|---|
| **Topology** | What the network looks like — interfaces, VLANs, tunnels, and subnets several firewalls share |
| **Access map** | Which zone reaches which, on which ports. Drag nodes to untangle, click to filter, right-click to hide |
| **Search** | Four kinds of lookup, see below |
| **Inventory** | List and filter interfaces, aliases, rules and NAT by IP / network / port |
| **Risk** | Which objects are exposed, who reaches a given port, and which deny-all rules do not actually deny |

### Four kinds of lookup

- **Across firewalls** — `A → B:port` walked through the whole chain. It only
  passes if **every** hop allows it; the first hop that refuses is the one
  reported, with its firewall, interface and rule.
- **Path check** — the same, but on **one** firewall, with a full trace of the
  rules examined. Useful when you want to study a single ruleset.
- **From** — everywhere one source can reach. The result is a **complete**
  partition of the space (addresses × ports), not a sample.
- **To** — everyone who can reach one destination, grouped by inbound interface.

Every field accepts an IP, a CIDR, an alias name, or an interface name.

**A subnet is a set of addresses, and the ruleset may treat parts of it
differently.** Enter one host and you get a single verdict with the full trace;
enter a subnet, alias or interface and you get a **table of regions**, each part
of the space with its own verdict. One quarantined host inside an otherwise
permitted `/24` shows up as its own `block` row rather than disappearing into a
single answer.

**`any` is not one question either.** A rule naming `tcp` says nothing about
`udp`. Asking for `any` checks each protocol on its own and reports `partial`
when they disagree, with a per-protocol breakdown. `partial` is deliberately
shown in a different colour from `pass` — reading it as "allowed" is the mistake
worth preventing.

---

## The things most worth knowing

This tool simulates `pf`, and the parts that are easiest to get wrong are handled
explicitly:

- **Floating rules are not `quick` by default**, interface rules are. A floating
  rule that matches can still be overridden by an interface rule after it.
  Treating this as first-match-wins gives the wrong answer.
- **The `match` action decides nothing.** It assigns a queue and lets evaluation
  continue. Treating it as `block` turns a floating shaper rule into a wall
  across the whole interface.
- **Destination NAT is applied before filtering.** The rule that allows the
  traffic points at the translated internal address, not the public one.
- **VPN tunnel rules live on the pseudo-interfaces** `openvpn` / `enc0`, not on a
  configured interface.

`explore_from` and `check` are two different ways of computing the same
semantics, and a test asserts they **always** agree — across every fixture in the
tree, including the ones with NAT and multiple firewalls, and for `any` as well
as a named protocol.

## Limits, stated up front

- **The parser follows the pfSense 2.7 schema and has not been fully validated.**
  Nine fields were added after meeting real configs (`srcmac`, `dstmac`,
  `bridgeto`, `match`, `source_hash_key`, `ipprotocol`, `statepolicy`, `pflow`,
  `target_subnet`). Anything still missing will show up in the warning list.
- **The firewall chain stops when a next hop belongs to a device that was not
  loaded.** The interface says it stopped and where. It does **not** claim the
  unchecked part is reachable.
- **State tables and reply traffic are not simulated.** Every verdict is for the
  first packet of a connection.
- **`srcmac` / `dstmac` / `bridgeto` are not simulated.** Rules using them match
  fewer packets in reality, so results involving them may be **broader** than the
  truth. The parser warns every time it sees one.
- **Outbound NAT does not affect verdicts** — it is shown for reference only.
- **No database.** Configs live in the backend process's memory; a restart loses
  them and you load again. That is also why the backend runs a **single** uvicorn
  worker.

---

## Architecture

```
backend/            FastAPI, no database, nginx is the only published port
  app/parser/       understands XML only, produces plain data types
  app/engine/       works on those types only, never touches XML
  app/api/          joins the two to HTTP
frontend/           Vite + React + TypeScript, builds to a static dist/
```

The parser ↔ engine boundary is what lets the engine be tested with hand-built
objects instead of XML files.

### API

Everything lives under `/api/v1`. Interactive docs at `/api/v1/docs` (HTTP Basic
auth, set `DOCS_USER` / `DOCS_PASSWORD` in `.env`).

| Method | Path |
|---|---|
| `POST` | `/configs` |
| `POST` | `/configs/{id}/firewalls` |
| `GET` `DELETE` | `/configs/{id}` |
| `GET` | `/configs/{id}/interfaces` `/aliases` `/rules` `/nat` |
| `GET` | `/configs/{id}/topology` `/access-graph` |
| `POST` | `/configs/{id}/query/path` `/check` `/from` `/to` |
| `GET` | `/configs/{id}/risk` `/risk/port` |

`/query/check` and `/query/path` return `kind: "point"` when both ends are a
single address, and `kind: "regions"` when either side is a set.

## Development

```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest && .venv/bin/ruff check app tests
```

```bash
cd frontend
npm install && npm run test && npm run lint
```

Or run the backend tests in a container: `cd backend && ./test.sh`.

Architecture details, conventions and the traps already hit are in
[BACKEND_GUIDE.md](BACKEND_GUIDE.md) and [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md).
The original design and implementation plans are in
[docs/superpowers/](docs/superpowers/).

## Offline

No CDN fonts, no map tiles, no network calls at runtime. Aliases of type `url`
and `urltable` are **not** fetched — they resolve to an empty set and any result
depending on them is marked `unresolved`.

Once the images are pulled, the whole system runs in an air-gapped environment.
