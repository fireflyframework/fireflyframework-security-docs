# Firefly Security Platform

> A state-of-the-art, enterprise-grade, **product-agnostic** hexagonal security platform built on
> Spring Security 6 and Project Reactor (WebFlux). It replaces and absorbs the legacy
> `fireflyframework-idp` broker and the custom resource-server / authorization code that was
> scattered across `fireflyframework-starter-application` and `fireflyframework-backoffice`.

- **Group / versioning:** `org.fireflyframework`, CalVer `26.MM.PP` (aligned with
  `fireflyframework-parent`, currently `26.06.01`).
- **Stack:** Java 21+, Spring Boot 3.x, Spring Security 6.x, Project Reactor. Servlet is confined
  to the optional authorization server.
- **Design spec:** [`docs/superpowers/specs/2026-06-18-fireflyframework-security-design.md`](../superpowers/specs/2026-06-18-fireflyframework-security-design.md).
- **Status:** 14 modules, all GREEN, published to `github.com/fireflyframework`. Every SPI port has
  a real adapter. Five integration tests run against live Docker containers (Postgres, OPA, Cerbos,
  OpenFGA, Vault). The IdP and application/backoffice de-domaining is complete. Only the cloud
  key/secret adapters (`aws-kms`, `azure-keyvault`) remain planned.

---

## 1. The problem this platform replaces

Firefly's "security" used to be **two disconnected halves** that never actually talked to each
other, sitting on top of a framework that had no real authentication enforcement:

- **Half 1 — the IdP broker** (`fireflyframework-idp` + four vendor adapters). A single *fat*
  reactive port (`IdpAdapter`, 21 methods plus a default `registerUser`) with 24 vendor-neutral
  DTOs and a 1:1 passthrough `IdpController` under `/idp`. The provider was chosen by
  `firefly.idp.provider`: **keycloak** (Admin Client + WebClient OIDC), **aws-cognito** (sync SDK
  v2), **azure-ad** (MSAL4J + Microsoft Graph), and **internal-db** (a real first-party auth
  service: R2DBC store, BCrypt(12), JJWT HS256, lockout, password policy/reset, TOTP).
- **Half 2 — resource-server / authz** (custom code in `starter-application` and `backoffice`).
  A bespoke AOP scheme: `@Secure` + `SecurityAspect` → `SecurityAuthorizationService`, an
  `EndpointSecurityRegistry`, an `AbstractSecurityConfiguration` DSL, a `JwtClaimsRoleExtractor`,
  a `SessionManager`/`SessionContext` "Security Center" SPI, and an `AppContext` principal facade.

The concrete defects this platform was built to close:

1. **No Spring Security in the framework.** No `oauth2ResourceServer`, no `ReactiveJwtDecoder`,
   no `SecurityWebFilterChain`, no method security, no JWKS. Only `spring-security-crypto` (BCrypt
   in internal-db) and a `SecurityExceptionConverter` mapping Spring Security exceptions into the
   kernel's RFC-7807 envelope were present.
2. **Inbound JWT signatures were never validated.** The azure-ad and keycloak adapters
   "introspected" tokens by decoding them locally with **no signature / issuer / audience
   checks** — a forged token reported `active=true`.
3. **Identity entered via a trusted `X-Party-Id` header.** The framework assumed an Istio/gateway
   had already terminated and verified the JWT, so any off-mesh caller could spoof an identity by
   setting a header.
4. **Fail-open by default.** `@Secure` silently skipped when no context argument was present;
   there was no global default-deny; `security.enforce` could turn enforcement off; and the
   starter pulled in `spring-boot-starter-security` with no chain, silently leaking Boot's
   HTTP-Basic default.
5. **The two halves did not connect.** Obtaining a token from `/idp` did nothing to populate the
   `AppContext` that the authorization aspect checked.
6. **firefly-oss product-domain leakage.** `X-Party-Id`, `partyId`, the business-role enum
   (`UserRoleEnum`: `AGENT`/`SUPER_AGENT`/`DISTRIBUTOR`/`ADMIN`), and a Contract/Product/RoleScope
   "Security Center" session model — all firefly-oss product-family concepts — were baked into
   framework code.

The Python (`fireflyframework-pyfly`) and Rust (`fireflyframework-rust`) ports already ship the
target shape: a security tier (Verifier / BearerLayer / FilterChain / OAuth2) cleanly separated
from an idp tier, joined by one thin token-validation seam. **That was the alignment target for
this Java platform, and it has now been met.**

---

## 2. Hexagonal architecture

The platform is a strict hexagon. Dependencies flow inward only; the core never imports a vendor
SDK, and every provider is an adapter behind an SPI.

```
api  ──►  spi  ──►  core  ──►  webflux  ──►  delivery  ──►  starters
                      ▲          (resource-server,             │
                      │           method-policy,               │
                      │           oauth2-client,               │
                      │           authorization-server)        │
                      └──────────────── adapters ◄─────────────┘
                          (opa · cerbos · openfga · vault · r2dbc)

           idp tier  ──[ TokenValidationPort ]──►  security tier
```

- **`api`** — driving ports (inbound use-cases) and the product-agnostic domain model:
  `SecurityPrincipal`, `Decision`/`Obligation`, `BearerToken`, `SigningKey`, `TrustedIssuer`,
  `SecurityAuditEvent`, the `@Secure` annotation, `AuthenticateUseCase`/`AuthorizeUseCase`, and
  security exceptions (`TokenValidationException`, `UnsupportedSecurityOperationException`). No
  Spring web or provider dependencies.
- **`spi`** — driven ports (interfaces only): the outbound contracts the core depends on.
- **`core`** — the framework-neutral engine: default token validators, authority normalization
  (absorbs `JwtClaimsRoleExtractor`), the `@Secure` authorization evaluator (fixed AND-semantics,
  real SpEL, default-deny), an embedded fail-closed policy decision adapter, an in-memory key/JWKS
  adapter, the bearer-token extractor, an introspection cache, and decorators. No provider or
  web-stack lock-in.
- **`webflux`** — reactive bindings: `ServerHttpSecurity` wiring, a `PolicyAuthorizationManager`
  URL PEP, a `FireflyAuthenticationToken`, and a Reactor-Context-backed `SecurityContextPort`
  accessor (`ReactorSecurityContextAdapter`).
- **delivery** — the four feature modules that bind the engine to a runnable Spring stack:
  `resource-server`, `method-policy`, `oauth2-client`, `authorization-server`.
- **starters** — `fireflyframework-starter-application` pulls the delivery modules so apps are
  secure by default; standalone services add the resource-server directly.
- **adapters** — one external SDK per adapter, each depending only on `spi`.

### The single seam: `TokenValidationPort`

The idp tier and the security tier connect through **exactly one SPI**:

```java
public interface TokenValidationPort {
    Mono<SecurityPrincipal> validate(BearerToken token);
}
```

It validates a presented bearer token — signature / issuer / audience / expiry for JWTs, RFC 7662
introspection for opaque tokens — and projects it into a `SecurityPrincipal`. It **never returns
an unvalidated principal**: any validation failure raises `TokenValidationException`. This mirrors
the pyfly/rust ports and keeps the two tiers decoupled; the IdP tier
(`fireflyframework-idp` + the Keycloak / Cognito / Entra / internal-db providers) knows nothing
about the security chain, and vice versa.

### The generic principal

`SecurityPrincipal` is an immutable record and the framework's stack-neutral principal facade —
a projection of a signature-validated authentication:

```
SecurityPrincipal { subject, issuer, tenantId?, authorities: Set<String>, scopes: Set<String>,
                    claims: Map<String,Object>, authTime?, acr?, amr, attributes: Map<String,Object> }
```

It deliberately carries **no** party, contract, or product. Products enrich it through
`PrincipalAttributeContributorPort` and read their own domain off `claims()` / `attributes()`. It
is propagated end-to-end via the Reactor Context.

---

## 3. The modules — every one, in one line

> **14 modules, all GREEN.** Each was built and tested with `mvn -o test` (exit 0), each carries
> at least one test, and the five infrastructure-backed adapters each carry a real-Docker
> integration test (see §7).

### The hexagon core (4)

| Module | One line |
|---|---|
| `fireflyframework-security-api` | Driving ports + product-agnostic domain: `SecurityPrincipal`, `Decision`/`Obligation`, `BearerToken`, `SigningKey`, `TrustedIssuer`, `SecurityAuditEvent`, `@Secure`, `Authenticate`/`AuthorizeUseCase`, security exceptions. |
| `fireflyframework-security-spi` | The 13 driven ports (interfaces only) — the complete outbound contract surface the core depends on. |
| `fireflyframework-security-core` | The vendor-neutral engine: `ConfigurableAuthorityMapper`, `SecureAuthorizationEvaluator`, `EmbeddedPolicyDecisionAdapter` (+`PolicyRule`), `InMemoryKeyManagementAdapter`, `CaffeineIntrospectionCache`, `BearerTokenExtractor`, `LoggingAuditEventAdapter`, `PrincipalFactory`. |
| `fireflyframework-security-webflux` | Reactive bindings: `FireflyAuthenticationToken`, `PolicyAuthorizationManager` (URL PEP), `ReactorSecurityContextAdapter` (`SecurityContextPort`), `PrincipalSupport`. |

### Delivery (4)

| Module | One line |
|---|---|
| `fireflyframework-security-resource-server` | Secure-by-default reactive OAuth2 resource server: `ResourceServerAutoConfiguration` (Nimbus verifying JWT decoder from `KeyManagementPort`, `JwtToFireflyPrincipalConverter`, default-deny chain, hardened headers) + `ResourceServerProperties`. |
| `fireflyframework-security-method-policy` | Reactive method security: `MethodSecurityAutoConfiguration` (`@EnableReactiveMethodSecurity`) + `SecureMethodAuthorizationManager` backing `@Secure` and `@PreAuthorize` with the core evaluator, fail-closed. |
| `fireflyframework-security-oauth2-client` | Reactive OAuth2/OIDC client (BFF): `OAuth2ClientAutoConfiguration` for authorization_code + PKCE, client_credentials, refresh, and a WebClient token-relay filter. |
| `fireflyframework-security-authorization-server` | **Servlet-only** Spring Authorization Server (`AuthorizationServerConfiguration`): OIDC discovery, JWKS, PKCE and grants, keys sourced from `KeyManagementPort`. Deployed separately from reactive resource servers. |

### Adapters — one SDK each, depending only on `spi` (5)

| Module | Implements | One line |
|---|---|---|
| `fireflyframework-security-adapter-opa` | `PolicyDecisionPort` | `OpaPolicyDecisionAdapter` — Open Policy Agent (Rego) ABAC, fail-closed. |
| `fireflyframework-security-adapter-cerbos` | `PolicyDecisionPort` | `CerbosPolicyDecisionAdapter` — Cerbos policy-as-code ABAC, fail-closed. |
| `fireflyframework-security-adapter-openfga` | `RelationshipPort` | `OpenFgaRelationshipAdapter` — Zanzibar-style ReBAC relationship checks. |
| `fireflyframework-security-adapter-vault` | `SecretsPort` | `VaultSecretsAdapter` — HashiCorp Vault secret retrieval, fail-closed at startup. |
| `fireflyframework-security-adapter-r2dbc` | `RevocationPort` | `R2dbcRevocationAdapter` — relational/R2DBC token revocation list (no external cache server required). |

### Test fixtures (1)

| Module | One line |
|---|---|
| `fireflyframework-security-test` | `TestPrincipals` factories and a configurable `FakePolicyDecisionPort` for asserting permit/deny paths without a live PDP. |

Plus the **refactored IdP tier**: `fireflyframework-idp` no longer carries `UserRoleEnum` or
`partyId`, its fat `IdpAdapter` is segregated into six capability ports (with `NotSupported`
defaults so all four provider adapters still build), and `fireflyframework-idp-keycloak` no longer
writes a `partyId`/`userRole` user attribute.

---

## 4. The 13 SPI ports and their adapter coverage

Every driven port has at least one real adapter — there are no orphan interfaces. The container
icon (🐳) marks adapters proven against a live service via Testcontainers.

| SPI port | Responsibility | Delivered adapter(s) | Planned |
|---|---|---|---|
| `TokenValidationPort` | **The idp↔security seam.** Validate a bearer → `SecurityPrincipal`; JWT → verifying decoder + JWKS, opaque → idp introspection + cache. | resource-server decoder (in-process RS256); idp `TokenIntrospectionPort` bridge | — |
| `KeyManagementPort` | Active/next signing keys, `kid`, JWKSource, rotation-with-overlap. | `InMemoryKeyManagementAdapter` (core; dev + in-proc RS256) | `aws-kms`, `azure-keyvault` |
| `SecretsPort` | Fetch secrets, lease renewal, fail-closed at startup. | `VaultSecretsAdapter` 🐳 (Vault) | `aws-kms`, `azure-keyvault` |
| `PolicyDecisionPort` | ABAC decide → PERMIT/DENY/INDETERMINATE + obligations, fail-closed. | `EmbeddedPolicyDecisionAdapter` (core); `OpaPolicyDecisionAdapter` 🐳; `CerbosPolicyDecisionAdapter` 🐳 | — |
| `RelationshipPort` | Zanzibar-style `check(subject, relation, object)` ReBAC. | `OpenFgaRelationshipAdapter` 🐳 (OpenFGA) | — |
| `RevocationPort` | Token/session revocation checks. | `R2dbcRevocationAdapter` 🐳 (PostgreSQL) | — |
| `AuthorityMappingPort` | Claims → authorities/scopes (dot-path config). | `ConfigurableAuthorityMapper` (core) | — |
| `TokenIntrospectionCachePort` | Cache opaque introspection, TTL bounded by `exp`. | `CaffeineIntrospectionCache` (core) | — |
| `SecurityContextPort` | Read the current validated principal (Reactor-context backed). | `ReactorSecurityContextAdapter` (webflux) | — |
| `AuditEventPort` | Sink for auth success/failure/denied/token/key events. | `LoggingAuditEventAdapter` (core) | — |
| `IssuerRegistryPort` | Trusted issuers + per-issuer decoder. | resource-server issuer wiring | — |
| `TenantResolverPort` | Resolve tenant from the request/principal into Reactor Context. | resource-server / core | — |
| `PrincipalAttributeContributorPort` | **Product extension seam** — enrich principal attributes/claims. | product-supplied (firefly-oss re-introduces its domain here) | — |

The only items still on the planned list are the cloud key/secret backends (`aws-kms`,
`azure-keyvault`); they are provider variants of `KeyManagementPort`/`SecretsPort` that cannot be
exercised against a local container, so they are deferred behind the in-memory key source and the
Vault secrets adapter that already cover today's needs.

---

## 5. Secure-by-default, hard

The whole point of the platform is to close the fail-open posture. There is **no shadow mode and
no audit-only mode** — the defaults are hard, and an application opts *out* of a route, never
*into* enforcement:

- **Default-deny.** The auto-configured `SecurityWebFilterChain` ends in
  `anyExchange().access(policyManager)`; nothing is reachable unless explicitly permitted.
- **Validated bearer always.** Every request is authenticated by an in-process verifying JWT
  decoder built from `KeyManagementPort`, with `iss` / `aud` / timestamp validators wired in.
- **Fail-closed everywhere.** PDP and introspection errors deny (never permit-on-error). A failing
  or throwing `@Secure` SpEL expression denies. A `null` principal is always denied.
- **Gateway-trusted headers are gone.** `X-Party-Id` is removed from the framework chain; identity
  comes only from a signature-validated `Authentication`. Mesh-internal callers must present a real
  bearer token.
- **No fail-open switch.** The legacy `security.enforce` bypass is removed; missing prod key
  sources fail startup rather than degrading silently.
- **Boot's auto HTTP-Basic chain is explicitly replaced** — `httpBasic`, `formLogin`, and
  `logout` are disabled on the reactive chain, so nothing leaks.
- **Hardened headers on every response** — HSTS (1 year, includeSubdomains), a locked-down CSP
  (`default-src 'none'; frame-ancestors 'none'`), `X-Frame-Options: DENY`, and a
  `no-referrer` Referrer-Policy. CSRF is off for pure bearer APIs.
- **Named, explicit opt-outs only.** Routes are permitted individually via
  `firefly.security.*` permit matchers; there is no global "allow all".
- **`requireAllRoles` / `requireAllPermissions` are honored** (the legacy aspect silently treated
  them as ANY).

Every bean in the resource-server auto-configuration is `@ConditionalOnMissingBean`, so
applications can override any single piece without losing the secure defaults for the rest.

---

## 6. Product-agnosticism — the de-domain (before → after)

The framework must be usable by any product, not just firefly-oss. The initiative purged every
firefly-oss domain concept framework-wide — from the IdP DTOs, from the application starter's
context/resolver/security stack, and from the parallel copy of that model in
`fireflyframework-backoffice`. (`fireflyframework-r2dbc` was already clean; `lumen-lending` samples
and `firefly-oss` doc references are legitimate product/sample code and out of scope.)

| Removed (firefly-oss leakage) | Where it lived | Replaced with (generic) |
|---|---|---|
| `X-Party-Id` trusted-header identity | `DefaultContextResolver`, `AppContext`, the `*ContextResolver`s, `AbstractApplicationController`/`AbstractResourceController` | identity only from a signature-validated `Authentication`, read via `SecurityContextPort` / `SecurityPrincipal` |
| `partyId` (UUID) field | idp `CreateUserRequest` / `IntrospectionResponse`; keycloak `IdpAdminServiceImpl` (wrote a `partyId` attribute) | `subject` (String) from the token; optional generic `attributes: Map<String,Object>` passthrough |
| `contractId` / `productId` / `scopeKey` / `subScopeKey` | `AppContext`, `SessionContext`, `BackofficeContext`, the `*SessionContextMapper`s | generic, nullable `tenantId` + open `attributes` map |
| `UserRoleEnum` (`AGENT`/`SUPER_AGENT`/`DISTRIBUTOR`/`ADMIN`) | idp `dtos/enums/UserRoleEnum.java` | plain `Set<String>` authorities — **enum deleted** |
| `ContractInfoDTO`, `ProductInfoDTO`, `RoleScopeInfoDTO` | starter-application `spi/dto` | **deleted** from the framework |
| `SessionManager` "Security Center" SPI + `SessionContext` | starter-application + backoffice | generic `PolicyDecisionPort` + `AuthorityMappingPort` + `SecurityContextPort`; firefly-oss re-implements its Security Center in its own code |

**The product extension seam.** `PrincipalAttributeContributorPort` lets firefly-oss (or any
product) re-introduce party/contract/product **in its own codebase**, reading them off
`SecurityPrincipal.attributes()` / JWT claims. The framework ships none of those fields.
`fireflyframework-backoffice` is refactored onto the generic `SecurityPrincipal`; its
party/contract context moves out to the product.

---

## 7. Verification evidence

The platform is not asserted to work — it is shown to. Beyond unit / contract tests, eight
integration tests exercise real cryptography and real services; **five spin up genuine Docker
containers** via Testcontainers.

### The 5 real-Docker integration tests

| Integration test | Container | What it proves |
|---|---|---|
| `R2dbcRevocationAdapterIntegrationTest` | `postgres:16-alpine` | Persistence, active-vs-expired distinction, idempotent upsert, and not-revoked default through the real `RevocationPort` (wired via `@DynamicPropertySource`). |
| `OpaPolicyDecisionAdapterIntegrationTest` | `openpolicyagent/opa:0.70.0` | A Rego policy is `PUT` to the server, then permit (allowed action / admin subject), deny (disallowed action for a non-admin), and **fail-closed** for an undefined decision path. |
| `CerbosPolicyDecisionAdapterIntegrationTest` | `cerbos/cerbos:latest` | The `PolicyDecisionPort` resolves real Cerbos PERMIT/DENY decisions, fail-closed on error. |
| `OpenFgaRelationshipAdapterIntegrationTest` | `openfga/openfga:latest` | Zanzibar-style `check()` returns true/false against a real OpenFGA store through the `RelationshipPort`. |
| `VaultSecretsAdapterIntegrationTest` | `hashicorp/vault:1.15` | The `SecretsPort` reads/writes secrets against a live Vault, with fail-closed behavior on a missing path. |

### The remaining integration tests (real crypto / WireMock / Spring contexts)

| Integration test | Against | What it proves |
|---|---|---|
| `ResourceServerIntegrationTest` | in-process RS256 crypto, random port + `WebTestClient` | A permit-matched route is open; a protected route is **401** without a token, **200** with a valid RS256 JWT signed by the active `KeyManagementPort` key (subject echoed), **401** for an expired or unknown-key token, **403** when a `PolicyRule` denies despite a valid token; hardened headers asserted present. |
| `AuthorizationServerIntegrationTest` | servlet `@SpringBootTest`, random port + `TestRestTemplate` | The `/.well-known/openid-configuration` discovery document, the published `/oauth2/jwks` (RSA keys), and a real `client_credentials` exchange at `/oauth2/token` returning a signed-JWT Bearer token. |
| `OAuth2ClientCredentialsIntegrationTest` | WireMock token endpoint | The authorized-client manager performs a real `client_credentials` exchange and the resolved access-token value is asserted. |
| `MethodSecurityIntegrationTest` | reactive security context | `@Secure` and `@PreAuthorize` both enforce fail-closed: deny when unauthenticated, allow when the required authority is present, deny when missing, and leave unannotated methods open. |

The `api`, `core`, `webflux`, `spi`, and `test` modules add focused unit / contract tests:
`SecurityPrincipalTest`, `DecisionTest`, `BearerTokenTest`, `SecureAuthorizationEvaluatorTest`,
`ConfigurableAuthorityMapperTest`, `EmbeddedPolicyDecisionAdapterTest`,
`InMemoryKeyManagementAdapterTest`, `CaffeineIntrospectionCacheTest`,
`PolicyAuthorizationManagerTest`, `ReactorSecurityContextAdapterTest`, `SpiContractTest`, and
`SecurityTestFixturesTest`. The de-domained application starter passes its full **180-test** suite
and the de-domained backoffice passes its **13-test** suite.

---

## 8. Where the platform is managed and delivered

The platform is wired into the framework's dependency and delivery plumbing through the parent and
the single BOM, and shipped to applications through the starter.

- **Dependency management — parent + BOM, in lockstep.** Observability and the whole security
  platform are version-managed in **`fireflyframework-parent`'s `dependencyManagement`** *and* in
  the single **`fireflyframework-bom`**. Both pin every `fireflyframework-security-*` module (and
  `spring-security-oauth2-authorization-server`) to `${project.version}` (`26.06.01`). Consumers
  import the BOM (or inherit the parent) and never spell out versions. (A standalone
  `fireflyframework-aggregator` reactor was briefly created and pushed, then **deleted** — local
  module and GitHub repo — in favor of this parent + BOM approach.)
- **Delivery — through the application starter.** `fireflyframework-starter-application` now
  depends directly on `fireflyframework-security-resource-server` **and**
  `fireflyframework-security-method-policy`, so every Firefly web app is locked down out of the
  box. `security-resource-server` transitively pulls `security-webflux` → `security-core` →
  `security-spi` → `security-api`; `security-method-policy` pulls `security-core` +
  `security-webflux`. Adding the starter therefore brings the whole secure chain. The resource
  server auto-configures only for reactive web apps and can be disabled with
  `firefly.security.resource-server.enabled=false`.

### Delivered two ways — with the starter, and without it

**With the application starter (secure-by-default).** Any application-tier service is locked down
out of the box — default-deny, verifying JWT validation, hardened headers, and `@Secure` reactive
method security — with **zero security code**. The service only declares which routes are public.

**Without the starter (standalone resource-server).** A service not on the application starter
adds `fireflyframework-security-resource-server` directly (and `-method-policy` for `@Secure`).
It receives the identical `ResourceServerAutoConfiguration`. Because the auto-config is conditional
on a reactive web application and gated by a single property, it composes cleanly with any service.

---

## 9. Request flow

```
Bearer token
  → security-webflux SecurityWebFilterChain
      → TokenValidationPort ──(JWT)──→ ReactiveJwtDecoder + JWKS(KeyManagementPort) + iss/aud/exp validators
                            ──(opaque)→ idp TokenIntrospectionPort + TokenIntrospectionCachePort
      → SecurityPrincipal (validated) → ReactiveSecurityContextHolder + Reactor Context (tenant, correlation)
      → URL PEP:    authorizeExchange (DEFAULT-DENY) + PolicyDecisionPort/RelationshipPort (ABAC/ReBAC, fail-closed)
      → Method PEP: @PreAuthorize / @Secure (security-method-policy)
      → controller / handler
  AuditEventPort emits at each decision point.
```

Authorization composes RBAC (authorities/scopes at the URL and method layers) with optional ABAC
(`PolicyDecisionPort`: embedded default, OPA, or Cerbos) and ReBAC (`RelationshipPort`: OpenFGA).
The default policy engine is embedded and fail-closed; production swaps in an adapter by declaring
a bean. `TokenValidationPort` is the single join between the idp and security tiers.

---

## 10. Repository / PR status

**14 new public repositories** under `github.com/fireflyframework`, all pushed to `main`, all
GREEN: `security-{api, spi, core, webflux, resource-server, method-policy, oauth2-client,
authorization-server, test}` and `security-adapter-{opa, cerbos, openfga, vault, r2dbc}`.

**Seven existing repositories** changed behind open, **unmerged** pull requests:

| Repository (`fireflyframework-…`) | PR | Branch | Change |
|---|---|---|---|
| `idp` | #13 | `feature/agnostic-de-domain` | segregate the fat `IdpAdapter` into capability ports + de-domain DTOs |
| `idp-keycloak` | #13 | `feature/agnostic-de-domain` | drop `partyId` / `userRole` user-attribute writes |
| `bom` | #22 | `feature/security-platform-bom` | manage the 14 security modules in the single BOM |
| `parent` | #30 | `feature/manage-observability-and-security` | observability + security in `dependencyManagement` |
| `starter-application` | #12 | `feature/wire-security-platform` | wire security + de-domain (180 tests green) |
| `backoffice` | #11 | `feature/agnostic-de-domain` | de-domain off the party/contract context (13 tests green) |
| `claude-skills` | #1 | `feature/security-skills` | security skills + agent (v1.21.0) |

Nothing is released to GitHub releases or Maven Central yet; the PRs are intentionally left open
for review.

---

## 11. Quick start

> Most applications get all of this implicitly via `fireflyframework-starter-application`. The
> snippets below show the explicit (standalone) form.

### 1. Add the resource server (or just the application starter)

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-resource-server</artifactId>
</dependency>
```

With `fireflyframework-bom` imported (or the parent inherited), the version is managed for you
(`26.06.01`). This pulls `security-webflux` → `security-core` → `security-spi` → `security-api`
transitively and activates `ResourceServerAutoConfiguration`. Depending on
`fireflyframework-starter-application` brings this plus `security-method-policy` automatically.

### 2. Configure (optional)

```yaml
firefly:
  security:
    resource-server:
      issuer: https://idp.example.com/        # adds a JwtIssuerValidator
      audiences: [ my-api ]                    # adds an audience validator
      role-claim-paths: [ realm_access.roles ] # dot-path claim → authority mapping
      scope-claim-paths: [ scope ]
      authority-prefix: "ROLE_"
      permit-matchers: [ /actuator/health, /actuator/info ]  # the only routes left open
```

With no configuration you still get the secure defaults: an in-memory dev signing key, default-deny
on every route, and the hardened header chain.

### 3. Authorize endpoints

```java
@Secure(roles = {"reader"})                        // ANY of these roles
@Secure(roles = {"a","b"}, requireAllRoles = true) // ALL of these roles (honored)
@Secure(expression = "principal.hasScope('orders:write')")
```

Everything not explicitly permitted is denied. PDP and introspection errors return **403**;
missing, expired, wrong-audience, wrong-issuer, unknown-`kid`, and forged-signature tokens return
**401**.

### 4. Extend without forking the framework

- Provide a `PrincipalAttributeContributorPort` bean to enrich `SecurityPrincipal.attributes()`
  with your product domain (party/contract/product), read off JWT claims.
- Provide `PolicyRule` beans for the embedded PDP, or swap in a real engine by declaring its bean:
  the **OPA** or **Cerbos** adapter for `PolicyDecisionPort`, the **OpenFGA** adapter for
  `RelationshipPort`.
- Add the **Vault** adapter for `SecretsPort` or the **R2DBC** adapter for `RevocationPort`.
- Override any auto-configured bean (`KeyManagementPort`, `AuthorityMappingPort`,
  `ReactiveJwtDecoder`, `SecurityWebFilterChain`, …) — each is `@ConditionalOnMissingBean`.

---

## 12. Status summary

- **GREEN today (delivered):** all 14 modules — `security-api`, `security-spi`, `security-core`,
  `security-webflux`, `security-resource-server`, `security-method-policy`,
  `security-oauth2-client`, `security-authorization-server`, `security-test`, and the five
  adapters (`-opa`, `-cerbos`, `-openfga`, `-vault`, `-r2dbc`). Every SPI port has a real adapter;
  five integration tests run against live Docker (Postgres, OPA, Cerbos, OpenFGA, Vault). The IdP
  tier is segregated into capability ports and de-domained; the application (180 tests) and
  backoffice (13 tests) layers are de-domained onto the generic `SecurityPrincipal`. Version-managed
  in both `fireflyframework-parent`'s `dependencyManagement` and `fireflyframework-bom`, delivered
  through `fireflyframework-starter-application` (→ resource-server + method-policy) and available
  standalone.
- **PLANNED:** only the cloud key/secret adapters — `fireflyframework-security-adapter-aws-kms`
  and `fireflyframework-security-adapter-azure-keyvault` (`KeyManagementPort` / `SecretsPort`
  provider variants) — plus deeper per-adapter hardening of the legacy IdP providers and merging
  the seven open PRs.
