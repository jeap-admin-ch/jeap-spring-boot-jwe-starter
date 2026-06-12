package ch.admin.bit.jeap.jwe.starter;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Minimal Spring Boot application used by the {@code @SpringBootTest} integration tests so the JWE
 * auto-configurations are picked up exactly as they would be in a real consuming service.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
class JweTestApplication {
}
