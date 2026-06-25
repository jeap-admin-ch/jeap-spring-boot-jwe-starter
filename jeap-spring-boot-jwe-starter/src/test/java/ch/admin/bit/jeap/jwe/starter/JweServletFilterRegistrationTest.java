package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import ch.admin.bit.jeap.jwe.web.JweFilterPaths;
import ch.admin.bit.jeap.jwe.web.JweServletFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the servlet-filter wiring contributed by {@link JweWebAutoConfiguration}:
 * registration on the servlet stack only, configurable ordering, and the include/exclude path model
 * (default API include; jEAP defaults for actuator/JWKS/metadata/SSE excluded, extended by config).
 */
class JweServletFilterRegistrationTest {

    private static final String[] STATIC_MODE = {
            "jeap.jwe.enabled=true",
            "jeap.jwe.test.enabled=true",
            "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0)
    };

    private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class))
            .withPropertyValues(STATIC_MODE);

    @Test
    void servletAppRegistersFilterWithDefaultOrder() {
        servletRunner.run(context -> {
            assertThat(context).hasSingleBean(JweServletFilter.class);
            assertThat(context).hasSingleBean(JweFilterPaths.class);
            assertThat(context).hasSingleBean(FilterRegistrationBean.class);
            assertThat(filterRegistration(context).getOrder())
                    .isEqualTo(JweProperties.Filter.DEFAULT_ORDER);
        });
    }

    @Test
    void defaultIncludeIsApiAndJeapEndpointsAreExcluded() {
        servletRunner.run(context -> {
            JweFilterPaths paths = context.getBean(JweFilterPaths.class);
            assertThat(paths.appliesTo("/api/orders")).isTrue();
            // Default include is API-only: static resources and the SPA shell are not filtered.
            assertThat(paths.appliesTo("/index.html")).isFalse();
            assertThat(paths.appliesTo("/actuator/health")).isFalse();
            assertThat(paths.appliesTo("/.well-known/jwks.json")).isFalse();
            assertThat(paths.appliesTo("/ui-api/sse/events")).isFalse();
        });
    }

    @Test
    void includedAndExcludedPathsAreConfigurable() {
        servletRunner.withPropertyValues(
                        "jeap.jwe.filter.included-paths[0]=/**",
                        "jeap.jwe.filter.excluded-paths[0]=/public/**")
                .run(context -> {
                    JweFilterPaths paths = context.getBean(JweFilterPaths.class);
                    assertThat(paths.appliesTo("/anything")).isTrue();
                    assertThat(paths.appliesTo("/public/docs")).isFalse();
                    // JWKS stays excluded even with a broadened include.
                    assertThat(paths.appliesTo("/.well-known/jwks.json")).isFalse();
                });
    }

    @Test
    void filterOrderIsConfigurable() {
        servletRunner.withPropertyValues("jeap.jwe.filter.order=42")
                .run(context -> assertThat(filterRegistration(context).getOrder()).isEqualTo(42));
    }

    @Test
    void disabledStarterRegistersNoFilter() {
        servletRunner.withPropertyValues("jeap.jwe.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(JweServletFilter.class));
    }

    @Test
    void nonServletApplicationRegistersNoFilter() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class))
                .withPropertyValues(STATIC_MODE)
                .run(context -> assertThat(context).doesNotHaveBean(JweServletFilter.class));
    }

    @SuppressWarnings("unchecked")
    private static FilterRegistrationBean<JweServletFilter> filterRegistration(ApplicationContext context) {
        return context.getBean(FilterRegistrationBean.class);
    }
}
