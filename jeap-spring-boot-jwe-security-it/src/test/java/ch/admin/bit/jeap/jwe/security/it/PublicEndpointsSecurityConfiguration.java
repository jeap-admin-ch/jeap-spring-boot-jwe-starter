package ch.admin.bit.jeap.jwe.security.it;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Opens a few <em>public</em> (unauthenticated) paths so the test can cover endpoints that are not
 * protected by jeap-security. This is the only security customization the test needs: it does
 * <strong>not</strong> re-declare the OAuth2 resource server — jeap-security already protects every
 * other path by default (its chain runs at lowest precedence). This higher-precedence chain merely
 * permits {@code /api/public/**} and {@code /public/**}, with CSRF disabled so unauthenticated
 * encrypted POSTs are not blocked.
 *
 * <p>Note the JWE filter applies independently of authentication: {@code /api/public/**} matches the
 * default JWE include ({@code /*api*}) and is therefore still encrypted even though it is public,
 * whereas {@code /public/**} is neither authenticated nor encrypted.
 */
@Configuration
class PublicEndpointsSecurityConfiguration {

    @Bean
    @Order(0)
    // S1130 is a false positive here: HttpSecurity#build() declares 'throws Exception', so the
    // declaration is required and cannot be removed without breaking compilation.
    @SuppressWarnings("java:S1130")
    SecurityFilterChain publicEndpointsSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/public/**", "/public/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
