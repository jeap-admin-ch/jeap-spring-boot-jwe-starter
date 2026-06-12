package ch.admin.bit.jeap.jwe.keymanagement;

import java.time.Duration;

/**
 * Bounded exponential-backoff settings for the resilient key refresh, derived from
 * {@code jeap.jwe.refresh.*}.
 *
 * @param initialBackoff delay before the first retry after a failed refresh
 * @param multiplier     factor applied to the delay between consecutive retries
 * @param maxBackoff     upper bound for the delay between retries
 * @param maxAttempts    maximum number of attempts per refresh cycle (at least one)
 */
public record JweRefreshRetrySettings(Duration initialBackoff, double multiplier, Duration maxBackoff,
                                      int maxAttempts) {

    public JweRefreshRetrySettings {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1 but was " + maxAttempts);
        }
        if (multiplier < 1.0) {
            throw new IllegalArgumentException("multiplier must be >= 1.0 but was " + multiplier);
        }
    }
}
