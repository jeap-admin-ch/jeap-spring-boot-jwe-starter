package ch.admin.bit.jeap.jwe.security.it;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Minimal Spring Boot application for the jeap-security coexistence integration test. With both the
 * JWE starter and {@code jeap-spring-boot-security-starter} on the classpath, this picks up the JWE
 * autoconfiguration <em>and</em> the jeap OAuth2 resource-server autoconfiguration exactly as a real
 * consuming service would, so the test exercises the two together.
 */
@SpringBootApplication
class JweSecurityTestApplication {
}
