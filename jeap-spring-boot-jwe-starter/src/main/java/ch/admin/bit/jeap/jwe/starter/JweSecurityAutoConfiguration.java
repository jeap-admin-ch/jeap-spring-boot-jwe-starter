package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.web.JweMetadataController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Makes the public JWE discovery endpoints reachable without authentication when the consuming
 * application secures its requests with Spring Security: the JWKS endpoint ({@code jeap.jwe.jwks.path})
 * and the protocol-metadata endpoint ({@code jeap.jwe.metadata.path}). Clients must fetch the public
 * key <em>before</em> they authenticate, so these paths have to be permitted; otherwise a secured
 * application would answer the unauthenticated discovery requests with {@code 401} and no client could
 * bootstrap.
 *
 * <p>It contributes a high-precedence {@link SecurityFilterChain} whose {@code securityMatcher} is
 * scoped to exactly these paths and that permits all requests. Because the matcher is narrow, every
 * other path falls through to the application's own (lower-precedence) chain. This composes with
 * {@code jeap-spring-boot-security-starter}, whose chains are registered at
 * {@link Ordered#LOWEST_PRECEDENCE} and are not {@code @ConditionalOnMissingBean}, so jeap-security keeps
 * protecting everything else.
 *
 * <p><strong>Caveat for plain Spring Boot security:</strong> if an application relies on Spring Boot's
 * auto-generated default security chain (Spring Security on the classpath, but no jeap-security and no
 * own {@code SecurityFilterChain}), contributing this chain makes that default back off
 * ({@code @ConditionalOnDefaultWebSecurity}). jeap services always register their own protect-all chain,
 * so this does not affect them; for the rare plain-default case, disable this via
 * {@code jeap.jwe.security.permit-well-known-endpoints=false} and permit the paths yourself.
 *
 * <p>The auto-configuration is gated on {@link ConditionalOnClass} for the Spring Security types and on
 * {@link ConditionalOnBean} for an {@link HttpSecurity} bean. So it is a no-op both when Spring Security
 * is absent and when it is on the classpath but the application has not actually enabled web security
 * (no {@code HttpSecurity} bean) - it never fails a context that merely has the Spring Security jars
 * present. It is ordered after Spring Boot's servlet web-security auto-configuration so the
 * {@code HttpSecurity} bean (registered via {@code @EnableWebSecurity}) is visible to the condition.
 *
 * <p>It is additionally gated on an actual {@link JweMetadataController} bean rather than on
 * {@code jeap.jwe.enabled}: with the switch off the starter still publishes the disabled state at the
 * metadata endpoint (see {@link JweDisabledMetadataAutoConfiguration}), which a secured application
 * would otherwise answer with {@code 401}. Gating on the controller also means that suppressing the
 * endpoint via {@code jeap.jwe.metadata.publish-when-disabled=false} contributes no chain at all, so a
 * fully disabled starter stays as invisible to the application's security setup as it was before.
 */
@Slf4j
@AutoConfiguration(
        after = {JweWebAutoConfiguration.class, JweDisabledMetadataAutoConfiguration.class},
        afterName = {
                "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
                "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration"
        })
@ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class})
@ConditionalOnBean({HttpSecurity.class, JweMetadataController.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "jeap.jwe.security", name = "permit-well-known-endpoints",
        havingValue = "true", matchIfMissing = true)
public class JweSecurityAutoConfiguration {

    /**
     * Precedence of the well-known security chain. Deliberately negative so it stays ahead of the
     * application's catch-all chain (jeap-security uses {@link Ordered#LOWEST_PRECEDENCE}) <em>and</em>
     * of team-defined chains, which conventionally use {@code 0} or {@code 100} (the latter being the
     * order of the now-deprecated {@code WebSecurityConfigurerAdapter}). A value such as {@code 0} would
     * tie with a team chain that also uses {@code 0}, leaving the ordering - and thus which chain decides
     * the narrowly-matched discovery paths - non-deterministic. {@code -100} keeps this chain reliably in
     * front while leaving room for an application to override it explicitly if it ever needs to.
     */
    static final int WELL_KNOWN_SECURITY_ORDER = -100;

    /**
     * Permits unauthenticated access to the protocol-metadata path and, while JWE is switched on, to the
     * JWKS path. With the switch off there is no JWKS endpoint in the context, so that path is left out
     * of the matcher rather than permitted into a {@code 404}. The paths are matched
     * application-relative (Spring Security strips {@code server.servlet.context-path}), matching how the
     * controllers map them and how {@link org.springframework.security.web.util.matcher.RequestMatcher}
     * evaluates request paths, so the configured values are used verbatim without context-path prefixing.
     * CSRF is disabled on this chain - the endpoints are read-only ({@code GET}) and stateless.
     *
     * <p>Authorization is scoped defensively: only the read-only {@code GET} and {@code HEAD} methods are
     * permitted, plus {@code OPTIONS} so a cross-origin CORS preflight is not blocked here (the MVC
     * preflight handler that emits the CORS response headers runs after Spring Security and would
     * otherwise never be reached, since this scoped chain is the only one selected for these paths).
     * Every other method on these paths is denied rather than waved through to the controller.
     */
    @Bean
    @Order(WELL_KNOWN_SECURITY_ORDER)
    @ConditionalOnMissingBean(name = "jweWellKnownSecurityFilterChain")
    @SuppressWarnings("java:S4502")
    // CSRF is disabled here because this chain only covers the public, read-only (GET) well-known
    // endpoints (JWKS / protocol metadata); CSRF protects state-changing requests, of which there are none.
    SecurityFilterChain jweWellKnownSecurityFilterChain(HttpSecurity http, JweProperties properties) throws Exception {
        String[] wellKnownPaths = properties.isEnabled()
                ? new String[]{properties.getJwks().getPath(), properties.getMetadata().getPath()}
                : new String[]{properties.getMetadata().getPath()};
        http
                .securityMatcher(wellKnownPaths)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, wellKnownPaths).permitAll()
                        .requestMatchers(HttpMethod.HEAD, wellKnownPaths).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, wellKnownPaths).permitAll()
                        .anyRequest().denyAll())
                .csrf(AbstractHttpConfigurer::disable);
        log.info("Permitting unauthenticated access to the JWE discovery endpoint(s) {}.",
                String.join(", ", wellKnownPaths));
        return http.build();
    }
}
