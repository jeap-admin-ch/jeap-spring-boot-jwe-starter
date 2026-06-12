package ch.admin.bit.jeap.jwe.keymanagement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.time.Duration;

/**
 * Schedules the periodic JWE key refresh at a fixed delay, picking up Vault key rotations
 * without a restart.
 *
 * <p>The delay is the configured {@code jeap.jwe.refresh.interval}; the first refresh runs one interval
 * after startup (the keys are already loaded by then). Each run delegates to
 * {@link JweKeyRefresher#refresh()}, which retries with backoff and keeps serving the cached keys on a
 * transient outage.
 */
public class JweKeyRefreshScheduler implements SchedulingConfigurer {

    private static final Logger log = LoggerFactory.getLogger(JweKeyRefreshScheduler.class);

    private final JweKeyRefresher keyRefresher;
    private final Duration interval;

    public JweKeyRefreshScheduler(JweKeyRefresher keyRefresher, Duration interval) {
        this.keyRefresher = keyRefresher;
        this.interval = interval;
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        log.info("Scheduling periodic JWE key refresh every {}.", interval);
        registrar.addFixedDelayTask(this::runRefresh, interval);
    }

    void runRefresh() {
        try {
            keyRefresher.refresh();
        } catch (RuntimeException e) {
            log.warn("Scheduled JWE key refresh failed unexpectedly; continuing to serve the cached keys. "
                    + "Cause: {}", e.getMessage());
        }
    }
}
