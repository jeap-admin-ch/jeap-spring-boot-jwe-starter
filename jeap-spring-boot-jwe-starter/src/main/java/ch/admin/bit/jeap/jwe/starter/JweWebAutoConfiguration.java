package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.keymanagement.JweMetrics;
import ch.admin.bit.jeap.jwe.web.*;
import com.nimbusds.jose.EncryptionMethod;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Registers the web-facing parts of the JWE starter: the JWKS endpoint and the servlet filter that
 * transparently decrypts requests and encrypts responses. Only active for servlet web applications;
 * reactive (WebFlux) stacks are not supported.
 */
@Slf4j
@AutoConfiguration(after = JweAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JweWebAutoConfiguration {

    private static final String DEFAULT_ACTUATOR_BASE_PATH = "/actuator";
    private static final String DEFAULT_SSE_ENDPOINT = "/ui-api/sse/events";

    private final JweProperties properties;
    private final Environment environment;

    public JweWebAutoConfiguration(JweProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Bean
    JweJwksController jweJwksController(JweKeyStore keyStore) {
        return new JweJwksController(keyStore);
    }

    @Bean
    JweMetadataController jweMetadataController(JweFilterPaths filterPaths) {
        JweProperties.Filter filter = properties.getFilter();
        // The filter matches the application-relative path (context path stripped), so the configured
        // patterns and the JweFilterPaths bean are context-relative. Clients, however, match the full
        // request URL (which includes the context path), so the published metadata prefixes every path
        // with server.servlet.context-path - making includedPaths/excludedPaths/jwksPath directly usable
        // against the origin. With no context path the prefix is empty and the values are unchanged.
        String contextPath = normalizeContextPath(environment.getProperty("server.servlet.context-path", ""));
        JweConfigurationMetadata metadata = new JweConfigurationMetadata(
                List.copyOf(filter.getContentTypeAllowlist()),
                JweRsaKeys.KEY_ENCRYPTION_ALGORITHM.getName(),
                EncryptionMethod.A256GCM.getName(),
                prefix(contextPath, properties.getJwks().getPath()),
                filter.getResponseKeyHeader(),
                prefixAll(contextPath, filterPaths.includedPatterns()),
                prefixAll(contextPath, filterPaths.excludedPatterns()));
        return new JweMetadataController(metadata);
    }

    /**
     * Normalises {@code server.servlet.context-path} to either an empty string (root deployment) or a
     * value with a leading and no trailing slash, ready to prepend to an application-relative path.
     */
    private static String normalizeContextPath(String contextPath) {
        String trimmed = contextPath == null ? "" : contextPath.trim();
        if (trimmed.isEmpty() || trimmed.equals("/")) {
            return "";
        }
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed;
        }
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static List<String> prefixAll(String contextPath, List<String> paths) {
        return paths.stream().map(path -> prefix(contextPath, path)).toList();
    }

    private static String prefix(String contextPath, String path) {
        return contextPath.isEmpty() ? path : contextPath + path;
    }

    /**
     * The paths the filter applies to: the configured {@code jeap.jwe.filter.included-paths} (default
     * API paths) minus the excluded paths — the built-in jEAP defaults (actuator, JWKS, protocol
     * metadata, SSE) plus the user-configured {@code jeap.jwe.filter.excluded-paths}. Includes are
     * evaluated first, excludes second.
     */
    @Bean
    JweFilterPaths jweFilterPaths() {
        return new JweFilterPaths(properties.getFilter().getIncludedPaths(), buildExclusionPatterns());
    }

    @Bean
    JweServletFilter jweServletFilter(JweFilterPaths filterPaths, JweKeyStore keyStore,
                                      ObjectProvider<JweMetrics> metrics) {
        JweProperties.Filter filter = properties.getFilter();
        JweFilterSettings settings = new JweFilterSettings(
                filter.getContentTypeAllowlist(),
                filter.getResponseKeyHeader(),
                filter.isRequireEncryptedRequest(),
                filter.isRequireEncryptedResponse(),
                filter.getProblemTypeBaseUri(),
                filter.getMaxPayloadBytes());
        return new JweServletFilter(filterPaths, keyStore, settings, metrics.getIfAvailable(() -> JweMetrics.NOOP));
    }

    @Bean
    FilterRegistrationBean<JweServletFilter> jweServletFilterRegistration(JweServletFilter filter) {
        FilterRegistrationBean<JweServletFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(properties.getFilter().getOrder());
        registration.addUrlPatterns("/*");
        registration.setName("jweServletFilter");
        return registration;
    }

    private List<String> buildExclusionPatterns() {
        List<String> patterns = new ArrayList<>();

        String actuatorBasePath = environment.getProperty(
                "management.endpoints.web.base-path", DEFAULT_ACTUATOR_BASE_PATH);
        patterns.add(actuatorBasePath);
        patterns.add(actuatorBasePath + "/**");

        // Always exclude the JWKS and protocol-metadata endpoints - clients read them unencrypted.
        patterns.add(properties.getJwks().getPath());
        patterns.add(properties.getMetadata().getPath());

        // jEAP SSE carries only event IDs (no payload) and must not be encrypted.
        String sseEndpoint = environment.getProperty("jeap.sse.web.endpoint", DEFAULT_SSE_ENDPOINT);
        patterns.add(sseEndpoint);
        patterns.add(sseEndpoint + "/**");

        for (String userPattern : properties.getFilter().getExcludedPaths()) {
            if (StringUtils.hasText(userPattern)) {
                patterns.add(userPattern);
            }
        }

        log.debug("JWE filter exclusion patterns: {}", patterns);
        return patterns;
    }

    /**
     * Fails fast if the configured JWKS path collides with the actuator base path.
     */
    @PostConstruct
    void validateJwksPathDoesNotClashWithActuator() {
        String jwksPath = properties.getJwks().getPath();
        String actuatorBasePath = environment.getProperty(
                "management.endpoints.web.base-path", DEFAULT_ACTUATOR_BASE_PATH);
        if (jwksPath.equals(actuatorBasePath) || jwksPath.startsWith(actuatorBasePath + "/")) {
            throw new IllegalStateException(
                    "Configured JWKS path '%s' overlaps the actuator base path '%s'. Configure a distinct jeap.jwe.jwks.path."
                            .formatted(jwksPath, actuatorBasePath));
        }
    }
}
