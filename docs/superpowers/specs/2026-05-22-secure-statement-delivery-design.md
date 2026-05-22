# Secure Statement Delivery — Design

**Date:** 2026-05-22
**Status:** Approved for planning
**Brief:** "Develop a system to store customer account statements as PDF files and provide secure, time-limited download links to customers."

This is a take-home submission for a senior Java/Spring Boot role. The brief is deliberately open; this document captures the design that will be implemented.

---

## 1. Goals & non-goals

**In scope**
- Operators upload PDF account statements on behalf of customers.
- Operators issue secure, time-limited download links per statement.
- Customers download via the link only (no customer login).
- Links may be configured single-use (default) or capped multi-use.
- Statements are virus-scanned, format-validated, encrypted at rest with envelope encryption.
- Full audit trail of upload, scan, link issuance, link consumption.
- Production-shaped operational surface: structured logs, metrics, traces, health probes, RFC 7807 errors, rate limiting, TLS at the edge.

**Out of scope (called out in README §10)**
- Real KMS / HSM integration (a `KeyProvider` port is provided; only a local impl ships).
- Real identity provider (a dev-only token endpoint stands in for an enterprise IdP).
- Multi-region replication, customer-facing UI, statement generation/templating.
- Quotas, billing, customer self-service.

## 2. Stack

| Concern | Choice | Why |
|---|---|---|
| Language / runtime | Java 21 | LTS, virtual threads available, modern API. |
| Framework | Spring Boot 3.3 (LTS) | What's actually deployed in banking today; Spring Security 6 is mature here. Spring Boot 4 explicitly rejected to avoid presenting bleeding-edge as production-grade. |
| Build | Gradle 8, Kotlin DSL, version catalog | Reproducible, modular. |
| DB | Postgres 16 | Source of truth for metadata + audit; mature, JSONB for detail bag. |
| Object store | MinIO (S3-compatible) | Real S3 SDK, swap endpoint for AWS S3 in prod. |
| Cache / link store | Redis 7 | Authoritative link state with TTL, Lua for atomic consume, distributed rate-limit buckets. |
| AV | ClamAV (clamd) | Standard in this space; runs in compose. |
| Edge | Caddy | Self-signed TLS terminator in compose, one-line config. |
| Static analysis | Error Prone + NullAway | Catch nullability bugs at compile time. |
| Format | Spotless (google-java-format) | Single source of truth for style. |

## 3. Architecture

Hexagonal (ports & adapters), enforced via three Gradle modules:

```
:domain          pure Java, zero Spring. Aggregates, value objects, domain errors, domain services.
:application     use-cases, port interfaces, command/result types. Depends only on :domain.
:adapters        Spring Boot app. REST, JPA, S3, Redis, ClamAV, KMS, OAuth2 config. Depends on :application.
```

The compiler enforces the boundary: `:domain` cannot import Spring; `:application` cannot import an adapter. This produces a stronger separation signal than a single-module project that "tries to keep it clean."

Two HTTP surfaces in one app, different security postures:
- `/api/operator/**` — OAuth2 resource server (JWT bearer), scope-gated.
- `/api/public/download/{token}` — unauthenticated; token IS the credential.

Single process. The scan worker runs as a `@Scheduled` task inside the same Spring app, with `SELECT ... FOR UPDATE SKIP LOCKED` for safe parallel scaling later.

### 3.1 Domain (`:domain`)

```
Statement (aggregate)        id, customerId, filename, sizeBytes, sha256 (plaintext digest),
                             mediaType, status (QUARANTINED | AVAILABLE | REJECTED | DELETED),
                             rejectionReason?, storageKey, encryptedDek, dekKeyId,
                             createdAt, createdBy. Status transitions on methods, not setters.

DownloadLink (aggregate)     id (= opaque token), statementId, customerId, expiresAt,
                             maxDownloads, remainingDownloads, revokedAt?, createdAt, createdBy.
                             consume(Clock) -> Result<DownloadGrant, LinkError>.

Value objects                CustomerId, StatementId, Sha256, MediaType, ByteSize.
                             Validation in the constructor; no stringly-typed IDs leak out.

Sealed domain errors         LinkExpired | LinkExhausted | LinkRevoked | LinkNotFound |
                             StatementNotAvailable | PdfInvalid | ContentTooLarge | ScanRejected.
```

Domain has no I/O and no static `Instant.now()` calls. Time is injected via `Clock`.

### 3.2 Application (`:application`)

Use-cases, one class per public action, single `execute(Command) -> Result` method:

```
UploadStatementUseCase
PromoteOrRejectStatementUseCase   (called by scan worker)
IssueDownloadLinkUseCase
ConsumeDownloadLinkUseCase
RevokeDownloadLinkUseCase
ListStatementsForCustomerUseCase
```

Ports (interfaces, implemented in `:adapters`):

```
StatementRepository       persistence of Statement metadata
DownloadLinkStore         atomic create / consume / revoke (Redis impl)
ObjectStorageGateway      putQuarantine, promote, openStream, delete (S3 impl)
KeyProvider               wrapDek / unwrapDek — KMS seam
ContentScanner            scan(bytes) -> Clean | Infected(signature) | Error
PdfValidator              validate(bytes) -> Valid | Invalid(reason)
TokenGenerator            newToken() -> 256-bit base64url
AuditLog                  append(AuditEvent) — structured, append-only
Clock
```

### 3.3 Adapters (`:adapters`)

Thin controllers; business logic stays in use-cases.

```
OperatorStatementsController     POST /api/operator/statements
                                  GET  /api/operator/customers/{id}/statements
OperatorLinksController          POST /api/operator/links
                                  DELETE /api/operator/links/{id}
PublicDownloadController         GET  /api/public/download/{token}
HealthController                 Actuator with split liveness/readiness
```

Adapter implementations:

```
JpaStatementRepository           Spring Data JPA + Flyway migrations
RedisDownloadLinkStore           Lua script for atomic consume
S3ObjectStorageGateway           AWS SDK v2, MinIO endpoint
LocalKeyProvider                 KEK from a mounted file; AES-256-GCM wrap. KmsKeyProvider seam ready.
ClamdContentScanner              TCP INSTREAM to clamd
PdfBoxValidator                  magic byte + structural parse via Apache PDFBox
StructuredJsonAuditLog           SLF4J + logstash-encoder; dedicated logger name; traceId/spanId.
```

Cross-cutting:
- `RateLimiter` — bucket4j-redis, applied via filter to public download and operator endpoints.
- `GlobalExceptionHandler` — every exception maps to RFC 7807 `application/problem+json`.
- `OpenApiConfig` — springdoc-openapi; `/openapi.json` and `/swagger-ui`.
- `ObservabilityConfig` — Micrometer + Prometheus, Micrometer Tracing, optional OTLP exporter.

## 4. Flows

### 4.1 Upload

1. Operator `POST /api/operator/statements` with JWT (`scope=statements:write`), multipart `file` + `customerId`.
2. Spring Security validates JWT, scope. RateLimiter check (per client id, 60/min).
3. Multipart size limit enforced early (Spring + manual cap) → 413 on breach.
4. `UploadStatementUseCase.execute(cmd)`:
   - `PdfValidator.validate(bytes)` → `Invalid` ⇒ 415.
   - SHA-256 of plaintext computed.
   - DEK generated (AES-256), `KeyProvider.wrapDek(dek)` returns ciphertext DEK + `dekKeyId`.
   - Bytes encrypted AES-256-GCM (12-byte random IV prepended, 16-byte tag appended).
   - `ObjectStorageGateway.putQuarantine(uuid, ciphertext, metadata)`.
   - `StatementRepository.save(QUARANTINED)`.
   - `AuditLog.append(UPLOADED)`.
5. Response: `202 Accepted`, `Location: /api/operator/statements/{id}`, body includes `status: QUARANTINED`.

`202` not `201`: the statement is not yet downloadable. Honest about async state.

### 4.2 Scan worker

Runs every 5 s in the app.

```
@Scheduled(...)
1. repo.findQuarantinedBatch(limit=10) WITH FOR UPDATE SKIP LOCKED
2. for each statement:
   ciphertext = storage.get(quarantineKey)
   plaintext  = decrypt(ciphertext, unwrap(dek))
   result     = scanner.scan(plaintext)
   Clean    -> storage.promote(quarantine -> available); repo.markAvailable(); audit(SCAN_PASSED)
   Infected -> storage.delete(quarantineKey); repo.markRejected(signature); audit(SCAN_REJECTED, signature)
   Error    -> leave; bump failure counter; >N => markRejected("scan_error")
```

`promote` uses S3 server-side `CopyObject` then `DeleteObject` — bytes do not round-trip through the app.

### 4.3 Issue link

`POST /api/operator/links` `{ statementId, ttlSeconds, maxDownloads=1 }`:

- Assert `statement.status == AVAILABLE` else 409.
- `token = TokenGenerator.newToken()` (32 random bytes → base64url).
- `DownloadLinkStore.create(token, { statementId, customerId, expiresAt, remainingDownloads })`
  → `SET link:<token> <json> EX <ttl> NX`.
- `AuditLog.append(LINK_ISSUED, link_token_hash = sha256(token))`. **Raw token never written to logs or audit.**
- Return `{ url: "https://.../api/public/download/<token>", expiresAt }`.

### 4.4 Download

`GET /api/public/download/{token}`:

- RateLimiter check (per source IP, 10/min) → 429.
- `ConsumeDownloadLinkUseCase.execute(token)`:
  - `DownloadLinkStore.consume(token)` runs a Lua script atomically:
    ```
    local v = redis.call('GET', KEYS[1])
    if not v then return cjson.encode({err='NOT_FOUND'}) end
    -- decode JSON; check expiresAt > now and not revoked; decrement remaining
    -- if remaining <= 0 -> DEL; else -> SET preserving TTL via PEXPIRE
    -- return grant or {err=...}
    ```
  - Any non-grant result ⇒ map to `LinkInvalid` ⇒ **uniform 404** (no oracle on existence vs expiry vs exhaustion).
- Fetch `Statement` by id from repo.
- `KeyProvider.unwrapDek(stmt.encryptedDek, stmt.dekKeyId)` → DEK.
- `ObjectStorageGateway.openStream(stmt.storageKey)` → ciphertext `InputStream`.
- Wrap with a `CipherInputStream` (AES/GCM/NoPadding) reading IV from prefix.
- Stream to response. Headers:
  ```
  Content-Type: application/pdf
  Content-Disposition: attachment; filename="<safe>"
  Content-Length: <plaintext size from row>
  X-Content-Digest: sha-256=<hex of stored plaintext sha256>
  Cache-Control: private, no-store
  ```
- `AuditLog.append(DOWNLOAD_SUCCESS, ip, userAgent, link_token_hash)`.

Streaming, not buffered: a 100 MB PDF must not blow heap.

## 5. Data model

### 5.1 Postgres (Flyway)

```sql
create table statement (
    id              uuid        primary key,
    customer_id     varchar(64) not null,
    filename        varchar(255) not null,
    size_bytes      bigint      not null check (size_bytes > 0),
    media_type      varchar(64) not null,
    sha256          bytea       not null,
    status          varchar(16) not null,
    rejection_reason varchar(255),
    storage_key     varchar(512) not null,
    encrypted_dek   bytea       not null,
    dek_key_id      varchar(64) not null,
    created_at      timestamptz not null default now(),
    created_by      varchar(128) not null,
    updated_at      timestamptz not null default now()
);
create index statement_customer_status_idx
    on statement (customer_id, status, created_at desc);
create index statement_status_quarantined_idx
    on statement (status, created_at) where status = 'QUARANTINED';

create table audit_event (
    id              bigserial   primary key,
    occurred_at     timestamptz not null default now(),
    event_type      varchar(32) not null,
    actor           varchar(128),
    actor_ip        inet,
    statement_id    uuid,
    link_token_hash bytea,
    detail          jsonb        not null default '{}'::jsonb,
    trace_id        varchar(32)
);
create index audit_event_statement_idx on audit_event (statement_id, occurred_at desc);
create index audit_event_type_time_idx on audit_event (event_type, occurred_at desc);
```

Notes:
- `sha256 bytea` (32 bytes) — hex only at the API edge.
- `encrypted_dek` + `dek_key_id` — rotating KEK does not require re-encrypting objects, only rewrapping DEKs.
- `storage_key` mutates from `quarantine/{uuid}` to `available/{uuid}` on promotion.
- `link_token_hash`, never the raw token. Audit dump leak ≠ replayable links.
- Partial index keeps the worker poll fast as the table grows.

### 5.2 Redis

```
link:<token>                JSON { statementId, customerId, expiresAt, remainingDownloads, revokedAt, issuedBy }
                            TTL = expiresAt - now() at SET time.
rl:download:ip:<ip>         bucket4j bucket
rl:operator:upload:<sub>    bucket4j bucket
rl:operator:links:<sub>     bucket4j bucket
```

Redis is authoritative for link state. Losing Redis = losing outstanding links; operators regenerate. This is acceptable and documented.

### 5.3 Object storage

```
Bucket: statements
  quarantine/<statementUuid>      ciphertext, just-uploaded
  available/<statementUuid>       ciphertext, scan-passed

Bucket: statements-kms (compose only)
  kek/<keyId>                     KEK bytes for LocalKeyProvider
```

- Object key is just the UUID. No customer id in the key. Linkage lives only in Postgres.
- MinIO server-side encryption (`AES256`) is also enabled — belt-and-braces over the client-side envelope encryption.

### 5.4 Object envelope

```
[12-byte IV][ciphertext][16-byte GCM auth tag]
```

`Cipher.getInstance("AES/GCM/NoPadding")`. DEK lives in Postgres (wrapped), not in the object.

## 6. Security

### 6.1 Authentication / authorization

- Operator API → OAuth2 resource server, RS256 JWT, JWKS from `OAUTH_JWKS_URI`.
- Compose ships a dev `/dev/token` endpoint (guarded by `DEV_TOKEN_SECRET`) for local dev/tests. Disabled in `prod` profile.
- Scopes: `statements:write`, `statements:read`, `links:write`.
- `@PreAuthorize` is applied at use-case entry, not controllers — authz survives controller refactors.
- Subject claim → `created_by` / audit `actor`.
- Actuator: `/actuator/health/{liveness,readiness}` public; everything else requires operator JWT.

### 6.2 Cryptography

- AES-256-GCM for object encryption; per-object random 12-byte IV. AEAD detects tampering.
- DEK per statement, KEK per `dekKeyId`. KEK rotation is a metadata-only operation.
- `LocalKeyProvider` reads KEK material from a file path supplied at runtime. `KeyProvider` port is the seam for AWS KMS / Vault — README documents the swap.

### 6.3 Validation

- PDF magic-byte check (`%PDF-`) + structural parse via PDFBox. Reject content-type spoofs.
- Hard size cap enforced before the body is fully read (Spring multipart + manual guard) → 413.

### 6.4 Tokens

- 32 random bytes (`SecureRandom`) → base64url. 256 bits of entropy.
- Stored in Redis under the token as key; comparisons are exact equality on the key (constant time at Redis level).
- Audit stores `sha256(token)`, never the raw value.

### 6.5 TLS

- Caddy fronts the app in compose, self-signed cert generated on first run, HSTS header set.
- App itself listens HTTP only inside the docker network. Documented: real deployment terminates TLS at the load balancer.

### 6.6 Rate limiting

- bucket4j-redis. Public download 10/min/IP; operator upload 60/min/sub; operator links 300/min/sub.
- Per-IP best-effort; real DDoS protection is the LB's job. Documented as such.

### 6.7 Threats explicitly addressed

| Threat | Defense |
|---|---|
| Link guessing | 256-bit token, uniform 404 on invalid |
| Link replay after expiry | TTL + Lua-atomic check |
| Link replay after consume (single-use) | Lua-atomic DECR/DEL |
| Malicious PDF reaching customer | ClamAV scan before AVAILABLE |
| Content-type spoof | PDFBox structural validation |
| Object-store breach | Client-side envelope encryption |
| Audit log breach → live token replay | Audit stores only `sha256(token)` |
| Operator credential leak | Scopes scoped narrowly; tokens short-lived; rate-limited |
| Tampered ciphertext | GCM authentication tag — decrypt fails noisily |
| Information disclosure via error messages | Uniform 404 for link errors; generic 500 body + traceId |

### 6.8 Threats *not* addressed (called out in README §10)

- Sophisticated DDoS — relies on infrastructure.
- KEK compromise — only a real KMS / HSM mitigates this; `LocalKeyProvider` is a dev convenience.
- Insider operator abuse beyond audit — needs separation of duties not in scope.
- Side-channel attacks on AES-GCM — out of scope.

## 7. Errors

Single `@RestControllerAdvice` produces `application/problem+json` (RFC 7807):

| Condition | Status |
|---|---|
| `PdfValidationException` | 415 |
| `ContentTooLargeException` | 413 |
| `RateLimitedException` | 429 + `Retry-After` |
| `StatementNotAvailable` | 409 |
| Any `LinkInvalid` (expired / exhausted / revoked / not found) | 404 |
| `AccessDeniedException` | 403 |
| Missing/invalid JWT | 401 |
| Anything else | 500, opaque body with `traceId`, full detail logged |

Rules:
- Domain layer throws domain exceptions or returns `Result`; only adapters know HTTP.
- Error bodies do not echo user input beyond what was just sent. No filename, no token, no SQL.

## 8. Observability

- **Logs:** Logback + logstash-encoder → JSON on stdout. `traceId`/`spanId` per request via Micrometer Tracing. Audit logger name `audit` for routing.
- **Metrics:** Micrometer + Prometheus at `/actuator/prometheus`. Custom:
  - `statement_uploaded_total`
  - `statement_scan_rejected_total{signature}`
  - `download_link_consumed_total{outcome}`
  - `download_bytes_total`
- **Tracing:** OpenTelemetry via Micrometer Tracing. OTLP exporter env-flagged.
- **Health:**
  - `/actuator/health/liveness` — process up.
  - `/actuator/health/readiness` — DB + Redis + S3 reachable. ClamAV deliberately excluded: scanner being down should not stop downloads.

## 9. Configuration & secrets

- All secrets via env vars, **no defaults**. App fails fast at startup if missing.
- `application.yml` references `${KEK_FILE_PATH}`, `${POSTGRES_PASSWORD}`, `${OAUTH_JWKS_URI}`, etc.
- `.env.example` checked in. Real `.env` git-ignored.
- KEK file mounted at runtime, never baked into the image.

### Profiles

| Profile | Purpose |
|---|---|
| `default` | Local dev outside Docker. Services on localhost. |
| `docker` | Image runs inside compose. Service names as hostnames. |
| `test` | Integration tests via Testcontainers. |
| `prod` | TLS required, dev-token endpoint disabled, debug actuators off. |

`SPRING_PROFILES_ACTIVE` is the only switch.

## 10. Testing strategy

Pyramid, all three layers:

### `:domain` — pure unit tests
- Statement state machine: legal/illegal transitions.
- `DownloadLink.consume()` table-driven: expired / exhausted / revoked / clean.
- Value object validation (Sha256, MediaType, CustomerId).
- High coverage, sub-second.

### `:application` — use-case tests with hand-rolled fakes
- One in-memory fake per port (`InMemoryStatementRepository`, `FakeKeyProvider`, `FakeContentScanner`, `FixedClock`, ...).
- Each use-case: happy path + every error branch.
- No Mockito; fakes are simpler, more honest, refactor-resilient.

### `:adapters` — slice + integration
Slice (`@WebMvcTest`, `@DataJpaTest`, `@JsonTest`) for tight, fast adapter checks.

Integration via Testcontainers (`@SpringBootTest` against real Postgres + Redis + MinIO + ClamAV):
- Full upload → scan → link → download golden path.
- EICAR string → scan rejection → 404 on link issue.
- Expired link → 404, no oracle.
- Single-use link consumed twice → first 200, second 404.
- Concurrent consume of single-use (10 threads) → exactly one 200.
- PDF magic-byte spoof (`.exe` renamed) → 415.
- Oversize upload → 413 *before* full body read.
- KEK rotation: rewrap DEK, decrypt with new KEK id still works.
- Ciphertext tamper: flip a byte → GCM auth failure → 500 (not 200).

Test PDFs generated at setup via PDFBox; EICAR for AV. No binary fixtures committed.

Mutation testing (Pitest) configured for `:domain` and `:application`. Not in CI by default (slow); README documents the command and the local kill rate.

## 11. Build & packaging

- Gradle 8 Kotlin DSL, `gradle/libs.versions.toml` version catalog.
- Spotless on `check`; Error Prone + NullAway compile checks.
- `bootJar` with layered jar enabled and `preserveFileTimestamps=false` for reproducibility.
- Multi-stage Dockerfile (Temurin 21 JDK → JRE). Non-root user. `MaxRAMPercentage=75`. `HEALTHCHECK` against liveness probe. ~200 MB final image.
- `docker-compose.yml` brings up: `app`, `postgres`, `redis`, `minio`, `clamav`, `caddy`. Single `docker compose up` → working `https://localhost`.

## 12. CI

GitHub Actions, one workflow, three jobs:

```
lint:    ./gradlew spotlessCheck
test:    ./gradlew check            (unit + slice + Testcontainers)
build:   ./gradlew bootJar && docker build (smoke run)
```

Gradle home cached. Testcontainers uses GHA's Docker daemon. Actions pinned by SHA.

## 13. README structure

1. What this is.
2. Quickstart — `docker compose up`, then `curl` to upload + download.
3. Architecture — diagram + hexagonal split summary.
4. Security model — threats addressed, threats not addressed.
5. API — link to Swagger UI / condensed table.
6. Configuration — env vars table.
7. Operations — health, metrics, logs.
8. Development — running outside Docker, profile table, test commands.
9. Design choices & trade-offs — Spring Boot 3 over 4, stateful tokens over JWT, MinIO over real S3, etc.
10. What I'd do with another week — real KMS, async scan via queue, OpenTelemetry collector wired in, chaos-test killing Redis mid-download.

§10 is deliberate: a senior submission should be honest about its limits.

## 14. Repository layout

```
secure-statement-delivery/
├── README.md
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── Caddyfile
├── settings.gradle.kts
├── build.gradle.kts
├── gradle/libs.versions.toml
├── domain/
│   ├── build.gradle.kts
│   └── src/{main,test}/java/...
├── application/
│   ├── build.gradle.kts
│   └── src/{main,test}/java/...
├── adapters/
│   ├── build.gradle.kts
│   └── src/{main,test}/{java,resources}/...
├── .github/workflows/ci.yml
└── docs/
    ├── superpowers/specs/2026-05-22-secure-statement-delivery-design.md   (this file)
    └── architecture.svg
```

## 15. Risks & open questions

- **Scope realism.** Maximalist scope is 3–5 days. Worth re-checking once the plan is broken into tasks; ready to drop the OTLP exporter or rate-limit module if a deadline tightens.
- **ClamAV in CI.** Container is ~250 MB and slow to boot. If CI time becomes a problem, the scan integration test moves behind a `slow` tag with a separate workflow job.
- **Spring Boot 3 vs 4.** Conservative choice. To be defended in the interview as a deliberate production-fit decision, not lack of awareness.
- **Hexagonal overhead.** Three modules is more ceremony than this size of system technically needs. Justified as a *demonstration* of the boundary, not as a runtime requirement.
