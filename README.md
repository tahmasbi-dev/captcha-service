# captcha-service

A self-contained CAPTCHA service: hands out image challenges, checks answers, and issues short-lived signed tokens that other servers redeem to prove a human solved a challenge. Runs with one command, keeps all its state in Redis, and never stores a solution in plain text.

## Running it

```bash
docker compose up -d --build
```

That starts Redis and the API together. The API is on `http://127.0.0.1:8000`, Redis on `127.0.0.1:6379` — both bound to loopback only, so nothing is exposed to the LAN. Without Docker: `docker compose up -d redis`, then `uv sync && uv run uvicorn captcha_service.api.app:app --port 8000`.

Settings come from `.env` (required: `CAPTCHA_INTERNAL_API_KEY` and `CAPTCHA_JWT_SECRET` — the app refuses to start without them).

## What it does, end to end

```
 client                 captcha-service                 resource server
   |                          |                               |
   |-- POST /challenges ----->|  generate code + PNG,         |
   |<-- id, image, expiry ----|  store hash in Redis          |
   |                          |                               |
   |-- POST /solve ---------->|  compare with stored hash     |
   |<-- JWT ------------- ----|  (wrong answer burns the      |
   |        challenge)        |                               |
   |                          |                               |
   |    client passes token + id to the resource server       |
   |                          |                               |
   |                          |<--- POST /internal/verify ----|
   |                          |  1. check X-Internal-Key      |
   |                          |  2. check JWT signature/exp   |
   |                          |  3. atomically consume the    |
   |                          |     solved challenge          |
   |                          |---- 200 valid (once) -------->|
```

### 1. `POST /v1/challenges` — get a puzzle

Send the action you're protecting (`{"action": "login"}`). The server picks 6 random characters (uppercase + digits, `secrets`-based, so no modulo bias), renders them into a distorted PNG, and stores only the **SHA-256 hash** of the code in Redis — the plaintext solution never touches storage, and it isn't in the response either.

You get back `challenge_id`, the image as a base64 data URL (drop it straight into `<img src>`), and `expires_at`. Challenges live 300 seconds by default.

### 2. `POST /v1/challenges/{id}/solve` — answer it

Send the action and what you read in the image. One try counts:

- **Correct** → the challenge flips to `solved`, you get an HS256 JWT. Its claims bind it to that exact challenge id and action, and it expires 300 seconds after issue.
- **Wrong** → the challenge flips to `failed` and is dead on the spot. No retry counter, no second chance — each brute-force attempt needs its own fresh challenge, which makes guessing economically pointless against the 31.7 billion possible 6-char codes.
- Already solved / failed / expired → `409`. Unknown id → `404`.

Every state write is a compare-and-set inside one Lua script keyed on a version counter, so two simultaneous solves of the same challenge can't both win — one gets the token, the loser gets `409 stale_challenge`.

### 3. `POST /v1/internal/verify` — redeem the ticket (server-to-server)

The resource server calls this with `{challenge_id, action, token}` and the `X-Internal-Key` header (compared in constant time). Three gates, in order:

1. **Header** — wrong or missing key, same terse `401` for both.
2. **Token** — the JWT signature, expiry, and issuer are checked; the token must be the one issued for *this* challenge id and *this* action or it's `400`.
3. **Redemption** — one atomic Lua script does all of the following as a single Redis operation:
   - if the challenge is `solved`: delete it, remove it from the expiry index, and record the verdict (bound to the SHA-256 of the exact token presented) for 120 seconds. Return **valid**.
   - if the verdict record exists and the *same* token hash retries: hand the recorded verdict back once, then delete the record. This is the network-glitch safety net — the caller that got disconnected mid-response retries and still succeeds. **Exactly one** retry reads it.
   - anything else (different token retrying, record and challenge both gone) → `404`, and a *different* token while a record is still alive → `400`.

The upshot: **one solved challenge buys exactly one successful verify, plus at most one replay of the same token.** Nobody can verify twice with a re-minted token, and the record on file can't be spent a second time either, even by its original owner.

## Why this holds up under concurrency

Everything a client can trigger that mutates state goes through a registered Lua script — Redis runs each atomically, with no other command slipping in between the read and the write:

- **solve** → CAS on the challenge `version` field. Losers get `StaleChallenge` (→ `409`) instead of clobbering.
- **verify** → the redeem script above. Checked under fire: 16 simultaneous verifies of one solved challenge produce one `200` and fifteen hard rejections. 50 concurrent saves of a fresh challenge produce exactly one winner.

Read paths (`get`, the expiry lookup) touch nothing mutable, so they can't race.

## Challenge lifecycle

```
            new / solve(correct)
   issued ────────────────► solved ──(first verify / replay)──► [deleted from Redis]
      │
      ├─ wrong answer ────► failed                    (terminal, deleted after TTL)
      └─ 5 min pass ──────► expired                   (terminal, deleted after TTL)
```

Terminal states are final. Each challenge hash carries a Redis TTL of `expires_at + 10 min grace` so expired rows get swept by Redis itself, and a sorted set (`challenge:expiry`) ordered by expiry timestamp is kept for due-for-expiry lookups.

## Endpoints

| Method | Path | Auth | What it does |
|---|---|---|---|
| POST | `/v1/challenges` | none | Issue a new challenge. `201` with `challenge_id`, `image` (data URL), `expires_at`. |
| POST | `/v1/challenges/{id}/solve` | none | Submit `{action, solution}`. `200` + `{token, expires_at}`; `400` wrong answer (burned); `409` not solvable / lost race; `404` unknown. |
| POST | `/v1/internal/verify` | `X-Internal-Key` | Verify + redeem a token. `200` on first use and on its single replay; see above for the rejection codes. |
| GET | `/v1/health` | none | Liveness with substance: pings Redis, reports whether the Lua scripts are still loaded. `503` when the store is unreachable. |
| GET | `/metrics` | none | Prometheus scrape endpoint (bound to loopback in dev). Latency per route/status, verify outcomes, solve right/wrong, stale CAS writes, Redis errors, expiry-queue size. |

Interactive docs at `/docs`.

Log line format is JSON (one object per line) and every request carries an `X-Request-ID` — set `X-Request-ID` on the way in to correlate, or read the minted one from the response header and quote it in a bug report.

## Configuration (env vars, `CAPTCHA_` prefix)

| Variable | Default | Notes |
|---|---|---|
| `INTERNAL_API_KEY` | required | shared secret for the internal verify endpoint |
| `JWT_SECRET` | required | signing key for solve tokens |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | pinned to IPv4 on purpose — see below |
| `REDIS_GRACE_SECONDS` | 600 | extra TTL beyond expiry so terminal states stay observable |
| `CHALLENGE_TTL_SECONDS` | 300 | how long a challenge stays solvable |
| `TOKEN_TTL_SECONDS` | 300 | JWT lifetime after a correct solve |
| `REDEMPTION_RETENTION_SECONDS` | 120 | how long a verdict stays on file for retries; must be < token TTL |
| `CAPTCHA_LENGTH / WIDTH / HEIGHT` | 6 / 280 / 90 | image dimensions and code length |

About `REDIS_URL`: `localhost` on Windows resolves to both `127.0.0.1` and `::1`. A Redis pool can quietly fill with connections to *two different servers*, and everything atomic suddenly isn't. Hence the explicit IPv4 default.

## Layout

Roughly hexagonal — the domain knows nothing about Redis or JWT:

```
src/captcha_service/
├── domain/            entities, value objects, state machine, ports (interfaces)
│   └── challenge.py     the Challenge aggregate + all its invariants
├── application/       use cases (issue / solve / verify) + DTOs + ports for clock, tokens
├── infrastructure/    Redis repository (CAS writes, Lua), proof ledger, JWT, image gen, clock
├── api/               FastAPI routes, schemas, exception handlers, auth dependency
└── core/settings.py   typed pydantic settings, fail-fast on missing secrets
```

Swapping Redis for anything else means writing one adapter that keeps the `ChallengeRepository` and `ProofLedger` contracts; nothing above the ports changes.
