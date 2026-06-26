package ch.admin.bit.jeap.jwe.keymanagement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resilient wrapper around {@link JweKeyLoader#refresh()} for the periodic refresh.
 *
 * <p>A transient Vault outage during a refresh must not break a running service: the cache is only ever
 * swapped on a fully successful export ({@link JweKeyLoader#refresh()} loads first and swaps last), so a
 * failed attempt leaves the most recently cached keys in place - decryption and the JWKS endpoint keep
 * working throughout the outage. This class adds <strong>bounded exponential-backoff retries</strong>;
 * if all attempts fail it logs a structured warning and returns normally (never throws), so the
 * scheduled task survives and recovers automatically on a later successful refresh.
 *
 * <p>This runtime tolerance is deliberately distinct from the startup fail-fast: after a
 * successful startup, transient outages are tolerated rather than fatal.
 */
public class JweKeyRefresher {

    private static final Logger log = LoggerFactory.getLogger(JweKeyRefresher.class);

    /**
     * Indirection over {@link Thread#sleep(long)} so backoff can be exercised deterministically in tests.
     */
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private final JweKeyLoader keyLoader;
    private final JweRefreshRetrySettings retry;
    private final JweMetrics metrics;
    private final Sleeper sleeper;

    public JweKeyRefresher(JweKeyLoader keyLoader, JweRefreshRetrySettings retry, JweMetrics metrics) {
        this(keyLoader, retry, metrics, Thread::sleep);
    }

    JweKeyRefresher(JweKeyLoader keyLoader, JweRefreshRetrySettings retry, JweMetrics metrics, Sleeper sleeper) {
        this.keyLoader = keyLoader;
        this.retry = retry;
        this.metrics = metrics;
        this.sleeper = sleeper;
    }

    /**
     * Attempts a refresh, retrying with exponential backoff up to {@code maxAttempts}. Returns without
     * throwing: on success the cache is swapped, on exhaustion the cached keys are kept.
     * Deliberatly not using spring-retry to keep the amount of dependencies low.
     */
    public void refresh() {
        long backoffMillis = retry.initialBackoff().toMillis();
        for (int attempt = 1; attempt <= retry.maxAttempts(); attempt++) {
            try {
                keyLoader.refresh();
                metrics.recordRefresh(true);
                return;
            } catch (JweKeyLoadException e) {
                if (attempt >= retry.maxAttempts()) {
                    log.warn("JWE key refresh failed after {} attempt(s); continuing to serve the cached keys. "
                            + "Cause: {}", attempt, e.getMessage());
                    metrics.recordRefresh(false);
                    return;
                }
                log.warn("JWE key refresh attempt {}/{} failed: {}. Retrying in {} ms.",
                        attempt, retry.maxAttempts(), e.getMessage(), backoffMillis);
                if (!sleep(backoffMillis)) {
                    return;
                }
                backoffMillis = nextBackoff(backoffMillis);
            }
        }
    }

    private long nextBackoff(long currentMillis) {
        long next = (long) (currentMillis * retry.multiplier());
        return Math.min(next, retry.maxBackoff().toMillis());
    }

    /**
     * Sleeps for the backoff; returns {@code false} if interrupted so the refresh aborts cleanly.
     */
    private boolean sleep(long millis) {
        try {
            sleeper.sleep(millis);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Interrupted during JWE key refresh backoff; aborting this refresh cycle.");
            return false;
        }
    }
}
