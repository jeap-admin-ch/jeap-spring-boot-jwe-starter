package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyLoader;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyRefreshScheduler;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyRefresher;
import ch.admin.bit.jeap.jwe.keymanagement.JweRefreshRetrySettings;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Enables the periodic key refresh and its outage resilience. Active when the starter
 * is enabled; the refresher and scheduler beans are contributed only outside the static test mode (no
 * Vault, no rotation) and once a {@link JweKeyLoader} is available. Ordered after the key-source and
 * key-store configurations.
 */
@AutoConfiguration(after = {JweAutoConfiguration.class, JweVaultAutoConfiguration.class})
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableScheduling
public class JweRefreshAutoConfiguration {

    @Bean
    @ConditionalOnBean(JweKeyLoader.class)
    @ConditionalOnProperty(prefix = "jeap.jwe.test", name = "enabled", havingValue = "false", matchIfMissing = true)
    JweKeyRefresher jweKeyRefresher(JweKeyLoader keyLoader, JweProperties properties) {
        JweProperties.Refresh refresh = properties.getRefresh();
        return new JweKeyRefresher(keyLoader, new JweRefreshRetrySettings(
                refresh.getInitialBackoff(), refresh.getBackoffMultiplier(),
                refresh.getMaxBackoff(), refresh.getMaxAttempts()));
    }

    @Bean
    @ConditionalOnBean(JweKeyRefresher.class)
    JweKeyRefreshScheduler jweKeyRefreshScheduler(JweKeyRefresher keyRefresher, JweProperties properties) {
        return new JweKeyRefreshScheduler(keyRefresher, properties.getRefresh().getInterval());
    }
}
