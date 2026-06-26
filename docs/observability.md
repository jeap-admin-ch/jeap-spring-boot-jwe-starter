# Observability (metrics)

The JWE starter exposes [Micrometer](https://micrometer.io) metrics so operators can monitor the
encryption subsystem and a **Governance service** can verify that end-to-end encryption is actually
active. Because the meters are plain Micrometer instruments, they are exported through whatever
registry the service already uses — Prometheus, OpenTelemetry, or any other supported backend.

## Enabling metrics

Metrics are **opt-in by dependency**: the starter depends on `micrometer-core` only as an *optional*
dependency, so nothing is pulled into a service that does not collect metrics. The meters activate
automatically as soon as the application context contains a Micrometer `MeterRegistry`.

In a typical jEAP service that means adding the `jeap-spring-boot-monitoring-starter` dependency, which brings in the
Micrometer core.

When no `MeterRegistry` bean is present, the starter falls back to a no-op and behaves exactly as
before — no meters, no behavioural change. There is no separate enable/disable property: the
presence of a registry is the switch.

## Exposed meters

All meters use the `jeap.jwe.*` name prefix (Prometheus renders dots as underscores). Tags are
bounded to enum/boolean values, so the metric cardinality stays low — there are no per-path or
per-request tags.

| Meter                            | Type                   | Tags                                       | Meaning                                                                                                                                                                           |
|----------------------------------|------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jeap.jwe.decryption`            | Timer (with histogram) | `result` = `success` / `failure`, `reason` | Inbound JWE-decryption outcome **and** latency, covering the request body **and** the `JWE-Response-Key` envelope unwrap (itself an RSA decryption). The `reason` tag carries the failure category (e.g. `unknown_key_id`, `malformed`, `decryption_failed`) or `none` on success. |
| `jeap.jwe.request.rejected`      | Counter                | `reason`                                   | Inbound requests rejected **before** the crypto layer by a size or policy guard — `reason` is `payload_too_large`, `encryption_required`, `response_encryption_required` or `response_key_required`. Complements the decryption meter so client-side encryption failures that never reach decryption stay visible. |
| `jeap.jwe.response.encryption`   | Counter                | `result` = `success` / `failure`           | Outbound response-encryption outcome (counted only when encryption is actually attempted, i.e. a successful response carrying a body).                                            |
| `jeap.jwe.key.refresh`           | Counter                | `result` = `success` / `failure`           | Outcome of each periodic Vault key-refresh cycle. A `failure` is recorded when a cycle exhausts its retries and keeps the cached keys.                                            |
| `jeap.jwe.key.refresh.timestamp` | Gauge (seconds)        | –                                          | Epoch seconds of the last successful refresh; seeded at startup from the initial key load, then updated on each periodic refresh. Useful to alert on staleness.                   |
| `jeap.jwe.keys.active`           | Gauge                  | –                                          | Number of active key versions currently accepted for decryption.                                                                                                                  |
| `jeap.jwe.keys.current.version`  | Gauge                  | –                                          | Numeric version of the current encryption key (newest active version); `0` when none is loaded.                                                                                   |
| `jeap.jwe.encryption.active`     | Gauge                  | –                                          | Governance signal, `1` or `0` — see below.                                                                                                                                        |

The decryption `Timer` publishes a percentile histogram, so the latency distribution is available as
the usual `jeap_jwe_decryption_seconds_bucket` / `_count` / `_sum` series in Prometheus, while the
`result` tag splits the same series into success and failure counts.

Key-version gauges are bound to the live, atomically-swapped key snapshot in the
`InMemoryJweKeyStore`, so they always reflect the current state — a rotation or an eviction is
visible at the next scrape without any push.

## Verifying end-to-end encryption (Governance)

`jeap.jwe.encryption.active` is the single gauge a Governance service can scrape to confirm that a
service genuinely enforces transparent JWE end-to-end encryption. It is `1` **only** when all of the
following hold, and `0` otherwise:

- JWE is enabled (`jeap.jwe.enabled` is `true`), and
- both directions are enforced — `jeap.jwe.filter.require-encrypted-request` **and**
  `jeap.jwe.filter.require-encrypted-response` are `true` (the secure defaults), and
- at least one encryption key is loaded (`jeap.jwe.keys.active` is greater than `0`).

If enforcement is relaxed for either direction, or the key store ends up empty, the gauge drops to
`0` — which is exactly the condition a governance check should alert on.

The gauge is also emitted as `0` when JWE is turned off entirely (`jeap.jwe.enabled=false`): a disabled
service therefore still reports `jeap_jwe_encryption_active 0` rather than dropping the series, so a
governance query (`jeap_jwe_encryption_active == 0`) reliably catches it instead of seeing nothing.

## Example queries

Prometheus (PromQL):

```promql
# Decryption failure rate over 5 minutes (request body + response-key envelope unwrap)
sum(rate(jeap_jwe_decryption_seconds_count{result="failure"}[5m]))

# All client-side encryption failures, including requests rejected before the crypto layer
sum(rate(jeap_jwe_decryption_seconds_count{result="failure"}[5m]))
  + sum(rate(jeap_jwe_request_rejected_total[5m]))

# 95th percentile decryption latency
histogram_quantile(0.95, sum(rate(jeap_jwe_decryption_seconds_bucket[5m])) by (le))

# Services where end-to-end encryption is NOT active
jeap_jwe_encryption_active == 0

# Seconds since the last successful Vault key refresh
time() - jeap_jwe_key_refresh_timestamp_seconds
```

## How it is wired

The Micrometer integration lives behind a small `JweMetrics` abstraction in the
`jeap-spring-boot-jwe-key-management` module (interface plus a `JweMetrics.NOOP` fallback). The only
Micrometer-aware implementation, `MicrometerJweMetrics`, is contributed by
`JweMetricsAutoConfiguration` in the starter, gated on a `MeterRegistry` being present. The servlet
filter and the key refresher receive the metrics through an `ObjectProvider`, falling back to the
no-op when metrics are not configured — so the crypto module stays free of any Micrometer dependency.
