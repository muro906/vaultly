# Vaultly

A secrets and environment-variable manager for small teams. Store credentials
encrypted at rest, promote them from development through staging to production,
see every change and every read, and hand CI/CD a narrowly-scoped token instead
of a person's credentials.

Go + Gin + PostgreSQL on the back, Next.js 14 App Router on the front.

---

## Why it exists

Most teams start with a `.env` file passed around in chat, then graduate to a
CI secret store that nobody can audit. Vaultly is the small step in between: a
service that keeps values encrypted, records who touched what, and makes
promoting a config change a deliberate, reviewable act.

## What it does

- **Encrypted at rest.** Every secret version is sealed with AES-256-GCM under
  its own data key, which is itself wrapped by a master key.
- **Full version history.** Values are append-only. Nothing is overwritten, so
  any version can be inspected, diffed and restored.
- **Environment promotion.** Copy values forward along `development → staging →
  production`, with a dry-run diff before anything is written.
- **Scoped machine tokens.** A CI token is bound to one project and one
  environment, with optional IP allowlisting, a request-rate cap and an expiry.
- **An audit log that includes reads.** Revealing a secret is recorded, not just
  changing one.
- **Roles that mean something.** A viewer can see that a secret exists and how
  it has changed, but never its value.

---

## Architecture

```
┌──────────────────────┐         ┌──────────────────────┐        ┌────────────┐
│  Browser             │         │  Next.js server      │        │  Go API    │
│                      │  HTML   │                      │  HTTP  │            │
│  • no tokens in JS   │◀───────▶│  • Server Components │◀──────▶│  • Gin     │
│  • httpOnly cookies  │         │  • Server Actions    │ cookie │  • services│
└──────────────────────┘         │  • forwards cookie   │forward │  • crypto  │
                                 └──────────────────────┘        └─────┬──────┘
                                                                       │
┌──────────────────────┐                                               │
│  CI / CD             │        Authorization: Bearer vlt_…            │
│  curl, GitHub Action │──────────────────────────────────────────────▶│
└──────────────────────┘         scoped to one environment             │
                                                                 ┌─────▼──────┐
                                                                 │ PostgreSQL │
                                                                 │ ciphertext │
                                                                 │ only       │
                                                                 └────────────┘
```

The browser never holds a token. The Next.js server reads the session cookie,
calls the Go API on the user's behalf, and returns rendered output — so a secret
value reaches the page only when the user explicitly asks to reveal one.

### Backend layout

```
backend/
├── cmd/api          server entrypoint, graceful shutdown
├── cmd/migrate      migration CLI
└── internal/
    ├── crypto       envelope encryption (build and read this first)
    ├── auth         Argon2id passwords, JWTs, opaque machine tokens
    ├── config       environment loading, validated once at startup
    ├── db           schema, embedded migrations, sqlc-generated queries
    ├── domain       shared types and sentinel errors
    ├── service      business logic and authorisation
    ├── http         Gin handlers, middleware, error mapping
    └── ratelimit    token-bucket limiter
```

---

## Security model

**Envelope encryption.** Each secret version gets a fresh random 32-byte data
encryption key (DEK). The value is sealed under the DEK with AES-256-GCM; the
DEK is then sealed under the master key. Two consequences:

- Rotating the master key rewraps only the DEKs. The ciphertext is never
  rewritten, so rotation costs the same whether you store ten secrets or ten
  million.
- Compromising a single DEK exposes exactly one version of one secret.

**Ciphertexts are bound to their location.** The secret's project, environment
and key are authenticated as GCM associated data. A ciphertext row copied from
`development` into `production`, or renamed to a different key, will not
decrypt. This is why promotion re-encrypts rather than copying rows.

**What is stored, and what is not:**

| Value | Stored as |
|---|---|
| Secret value | AES-256-GCM ciphertext, plus a wrapped DEK and nonce |
| Master key | Never stored — supplied via `VAULTLY_MASTER_KEY` at runtime |
| User password | Argon2id hash (19 MiB, 2 iterations), parameters encoded in the hash |
| Session refresh token | SHA-256 digest; rotated on every refresh |
| CI/CD access token | SHA-256 digest; the token itself is shown once and never again |

**Sessions.** A short-lived HS256 access token (15 minutes) plus an opaque
refresh token, both delivered as httpOnly cookies. The JWT pins its algorithm,
issuer and audience, which closes the `alg: none` and cross-service replay
paths. Refreshing rotates the refresh token and revokes the old one, so a
stolen token stops working the moment the real client next refreshes.

**Failing closed.** A missing resource and a forbidden one both return `404`, so
nobody can probe for workspaces they cannot see. An unrecognised role is treated
as no access rather than as a default.

### Threat model — what this does *not* protect against

Being explicit about the boundaries:

- **An attacker who has the master key and the database** can decrypt
  everything. The key is the whole secret; treat it accordingly.
- **A compromised API process** can decrypt any secret it is asked for, because
  it necessarily holds the master key in memory.
- **A malicious authorised user** can read every secret their role permits. The
  audit log records what they did; it does not prevent it.
- **Rate limiting is per process.** Behind N replicas the effective limit is N
  times the configured rate. It exists to stop runaway CI loops, not as a
  billing meter.
- **No secret scanning or automatic rotation.** Vaultly stores what you give it.

---

## Quickstart

Requirements: Docker and Docker Compose. (For running outside containers: Go
1.24+, Node 20+, PostgreSQL 16+.)

```bash
git clone <your-fork-url> vaultly
cd vaultly

cp .env.example .env
make keys >> .env      # appends a generated master key and JWT secret
$EDITOR .env           # remove the now-empty placeholder lines

make up                # postgres + api + web
```

- Web UI: <http://localhost:3000>
- API: <http://localhost:8080>

Register an account, and a personal workspace is created for you along with a
project's `development`, `staging` and `production` environments.

> **Keep the master key.** It is not stored anywhere. Lose it and every secret
> in the database becomes permanently unreadable.

### Running without Docker

```bash
make db                # just PostgreSQL
make migrate           # apply the schema
make run               # API on :8080

cd frontend && npm install && npm run dev   # UI on :3000
```

---

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | — | `postgres://…`; the scheme is validated |
| `VAULTLY_MASTER_KEY` | yes | — | Exactly 32 bytes, base64. `openssl rand -base64 32` |
| `JWT_SECRET` | yes | — | At least 32 characters. `openssl rand -base64 48` |
| `ACCESS_TOKEN_TTL` | no | `15m` | Must be shorter than the refresh TTL |
| `REFRESH_TOKEN_TTL` | no | `720h` | |
| `PORT` | no | `8080` | |
| `ENVIRONMENT` | no | `development` | `production` marks cookies Secure and logs JSON |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |
| `CORS_ALLOWED_ORIGINS` | no | `http://localhost:3000` | Explicit origins; `*` is rejected |
| `TRUST_PROXY` | no | `false` | See below |
| `API_BASE_URL` | frontend | `http://localhost:8080` | Server-side only, never exposed to the browser |

Configuration is validated once at startup and **every** problem is reported at
once, so a misconfigured deployment can be fixed in a single pass rather than
one restart per missing variable.

### A note on `TRUST_PROXY`

Leave it `false` unless the API sits behind a reverse proxy that overwrites
`X-Forwarded-For`. IP allowlisting and rate limiting both depend on the client
address being truthful; trusting the header unconditionally would let any
caller forge its own source address and walk straight through an allowlist.

---

## API reference

All routes are prefixed `/api/v1`. Human endpoints authenticate with the session
cookie (or `Authorization: Bearer <jwt>`); the `/cicd` endpoints authenticate
with a `vlt_` token.

### Auth
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Create an account and a personal workspace |
| `POST` | `/auth/login` | Start a session |
| `POST` | `/auth/refresh` | Rotate the session |
| `POST` | `/auth/logout` | Revoke the session |
| `GET` | `/auth/me` | The current user |

### Workspaces and members
| Method | Path |
|---|---|
| `GET` `POST` | `/workspaces` |
| `GET` | `/workspaces/:id` |
| `GET` `POST` | `/workspaces/:id/members` |
| `PATCH` `DELETE` | `/workspaces/:id/members/:memberId` |
| `GET` | `/workspaces/:id/audit-logs` — cursor-paginated, filterable |
| `GET` | `/workspaces/:id/audit-actions` |

### Projects and environments
| Method | Path |
|---|---|
| `GET` `POST` | `/workspaces/:id/projects` |
| `GET` `PATCH` `DELETE` | `/projects/:id` |
| `GET` `POST` | `/projects/:id/environments` |
| `POST` | `/projects/:id/promote` — `dryRun` for a preview |
| `GET` `POST` | `/projects/:id/tokens` |

### Secrets
| Method | Path | Notes |
|---|---|---|
| `GET` `POST` | `/environments/:id/secrets` | Listing never includes values |
| `GET` | `/secrets/:id` | Metadata only |
| `PUT` | `/secrets/:id` | New version; send `expectedVersion` for a conflict check |
| `PATCH` `DELETE` | `/secrets/:id` | |
| `GET` | `/secrets/:id/reveal` | Decrypts, and is audited |
| `GET` | `/secrets/:id/versions` | History without values |
| `GET` | `/secrets/:id/versions/:version` | One historical value; audited |
| `POST` | `/secrets/:id/versions/:version/rollback` | Appends the old value as a new version |

### Machine endpoints
| Method | Path |
|---|---|
| `GET` | `/cicd/secrets` — `?format=dotenv` for a `.env` rendering |

### Health
`GET /healthz` (liveness, no database) and `GET /readyz` (readiness, pings the
database).

---

## Using a token in CI

Create a token in the UI under **Project → Access tokens**, scoped to a single
environment. It is shown once.

```bash
curl -sS -H "Authorization: Bearer $VAULTLY_TOKEN" \
  "$VAULTLY_URL/api/v1/cicd/secrets?format=dotenv" > .env
```

Values are single-quoted with embedded quotes escaped, so a shell sourcing the
file will not perform substitution on a password containing `$` or `#`.

As JSON instead:

```bash
curl -sS -H "Authorization: Bearer $VAULTLY_TOKEN" \
  "$VAULTLY_URL/api/v1/cicd/secrets" | jq -r '.secrets'
```

A GitHub Actions step:

```yaml
- name: Load secrets
  env:
    VAULTLY_TOKEN: ${{ secrets.VAULTLY_TOKEN }}
  run: |
    curl -sS -H "Authorization: Bearer $VAULTLY_TOKEN" \
      "https://vaultly.example.com/api/v1/cicd/secrets?format=dotenv" >> "$GITHUB_ENV"
```

---

## Rotating the master key

Envelope encryption makes this cheap: only the wrapped data keys are rewritten,
never the ciphertext.

```bash
# 1. Generate the new key and check the rotation would succeed.
NEW_KEY=$(openssl rand -base64 32)

DATABASE_URL=postgres://…                \
VAULTLY_MASTER_KEY=$CURRENT_KEY          \
VAULTLY_NEW_MASTER_KEY=$NEW_KEY          \
  make rotate-key-check

# 2. Rotate for real.
DATABASE_URL=postgres://…                \
VAULTLY_MASTER_KEY=$CURRENT_KEY          \
VAULTLY_NEW_MASTER_KEY=$NEW_KEY          \
  make rotate-key

# 3. Set VAULTLY_MASTER_KEY to the new key and restart the API.
```

Between steps 2 and 3 the running API holds the retired key and **cannot
decrypt anything**, so plan the restart as part of the rotation.

The command commits one batch per transaction and is idempotent: a row already
wrapped under the new key is detected and skipped, so an interrupted run is
resumed simply by running the same command again.

---

## Roles

| | viewer | member | admin | owner |
|---|:-:|:-:|:-:|:-:|
| See which secrets exist, and their history | ✅ | ✅ | ✅ | ✅ |
| Reveal secret values | — | ✅ | ✅ | ✅ |
| Create, edit, roll back, promote | — | ✅ | ✅ | ✅ |
| Manage members and access tokens | — | — | ✅ | ✅ |
| Delete the project or workspace | — | — | — | ✅ |

Roles are enforced in the service layer, not only in middleware, so every path
into an operation is covered. The UI hides controls a role cannot use, but that
is a courtesy — the API checks independently.

---

## Testing

```bash
# Unit tests: crypto, auth, config, rate limiting. No database needed.
cd backend && go test ./...

# Integration tests against a real PostgreSQL.
# Starts a throwaway container, or set VAULTLY_TEST_DATABASE_URL to reuse one.
go test -tags=integration ./...

# Frontend
cd frontend && npm test && npx tsc --noEmit
```

What the tests actually assert, beyond the happy paths:

- A tampered ciphertext, a wrong nonce or a truncated wrapped key all fail to
  decrypt, and a ciphertext moved to another environment fails too.
- Master key rotation leaves the ciphertext byte-identical and the plaintext
  recoverable, while the retired key stops working.
- No stored ciphertext contains its plaintext, and no token's raw value is
  stored beside its digest — both read straight from the database.
- A login against an unknown address is indistinguishable from a wrong
  password.
- A replayed refresh token is rejected after rotation.
- A stale `expectedVersion` produces a `409` and the earlier write survives.
- A viewer gets `403` on every value-revealing route; a non-member gets `404`.
- A revealed value in the UI hides itself after ten seconds, hides when the tab
  is backgrounded, and a reveal that resolves after unmount is dropped.

---

## Design notes

A few decisions worth explaining, since they are the interesting part:

**Rollback copies ciphertext, promotion re-encrypts.** Restoring an old version
copies its ciphertext verbatim — the value is already sealed under that secret's
identity, so no plaintext passes through the process. Promotion cannot do that,
because the associated data binds a ciphertext to its environment, so values are
decrypted and re-sealed for the target.

**Audit writes are off the request path.** Events are queued and drained by a
background writer that batches them into one transaction. A secret read should
not wait on an `INSERT`. The trade-off is explicit: a hard kill loses whatever
is queued, so `Close` is wired into graceful shutdown and always flushes.

**Bulk decryption is bounded, not unbounded.** Pulling an environment decrypts
every value across a worker pool sized to the available cores. Decryption is
CPU-bound, so more goroutines would only add scheduling overhead — and the bound
also caps how much plaintext exists in memory at once.

**Version history is append-only.** Updates and rollbacks both insert. Nothing
in the system rewrites a version, which is what makes the audit trail
trustworthy and the diff view possible.

**Keyset pagination for the activity feed.** The log is append-heavy, and an
`OFFSET` scan would both slow down and skip rows as new entries arrive while
someone is paging.

---

## Known limitations

- **Next.js advisories.** The pinned `next@14.2.35` is the latest 14.x release
  and carries no known critical issues, but several moderate/high advisories
  affect the whole 14.x line with no fix available within it. They concern the
  image optimizer, i18n routing and rewrites — none of which this app uses.
  Moving to Next 15+ would clear them.
- Rate limiting is per process (see the threat model).
- No email delivery, so members must already have an account before being added.

---

## Deploying the frontend to Vercel

Set `API_BASE_URL` to your API's public address in the project's environment
variables. It is deliberately not a `NEXT_PUBLIC_` variable, so it is never
inlined into the browser bundle. The API must list your Vercel domain in
`CORS_ALLOWED_ORIGINS`, and should run with `ENVIRONMENT=production` so session
cookies are marked `Secure`.

---

## License

[MIT](LICENSE) © The Vaultly Authors
