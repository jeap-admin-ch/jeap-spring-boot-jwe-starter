package ch.admin.bit.jeap.jwe.web;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests {@link JweFilterPaths}: the filter applies when a path matches an include and no exclude
 * (includes first, excludes second).
 */
class JweFilterPathsTest {

    private static final List<String> DEFAULT_EXCLUDES = List.of(
            "/actuator", "/actuator/**",
            "/.well-known/jwks.json",
            "/.well-known/jwe-configuration",
            "/ui-api/sse/events", "/ui-api/sse/events/**");

    @Test
    void defaultApiIncludeAppliesToApiPathsAndTheirSubPaths() {
        // The default include "/*api*/**": first segment contains "api", plus everything under it.
        JweFilterPaths paths = new JweFilterPaths(List.of("/*api*/**"), List.of());
        assertThat(paths.appliesTo("/api")).isTrue();
        assertThat(paths.appliesTo("/api/orders")).isTrue();
        assertThat(paths.appliesTo("/api/orders/42")).isTrue();
        assertThat(paths.appliesTo("/v1api/orders")).isTrue();
    }

    @Test
    void defaultApiIncludeDoesNotApplyToNonApiPaths() {
        JweFilterPaths paths = new JweFilterPaths(List.of("/*api*/**"), List.of());
        assertThat(paths.appliesTo("/")).isFalse();
        assertThat(paths.appliesTo("/index.html")).isFalse();
        assertThat(paths.appliesTo("/assets/app.js")).isFalse();
    }

    @Test
    void excludesWinOverIncludes() {
        // "/ui-api/..." matches the api include but is excluded (SSE) -> not filtered.
        JweFilterPaths paths = new JweFilterPaths(List.of("/*api*/**"), DEFAULT_EXCLUDES);
        assertThat(paths.appliesTo("/ui-api/sse/events")).isFalse();
        assertThat(paths.appliesTo("/ui-api/sse/events/stream")).isFalse();
        assertThat(paths.appliesTo("/api/orders")).isTrue();
    }

    @Test
    void includeEverythingMinusExcludes() {
        JweFilterPaths paths = new JweFilterPaths(List.of("/**"), DEFAULT_EXCLUDES);
        assertThat(paths.appliesTo("/api/orders")).isTrue();
        assertThat(paths.appliesTo("/anything")).isTrue();
        assertThat(paths.appliesTo("/actuator")).isFalse();
        assertThat(paths.appliesTo("/actuator/health")).isFalse();
        assertThat(paths.appliesTo("/.well-known/jwks.json")).isFalse();
        assertThat(paths.appliesTo("/.well-known/jwe-configuration")).isFalse();
    }

    @Test
    void noIncludeMeansFilterNeverApplies() {
        JweFilterPaths paths = new JweFilterPaths(List.of(), DEFAULT_EXCLUDES);
        assertThat(paths.appliesTo("/api/orders")).isFalse();
    }

    @Test
    void patternsAreExposedImmutably() {
        JweFilterPaths paths = new JweFilterPaths(List.of("/*api*/**"), List.of("/actuator/**"));
        List<String> included = paths.includedPatterns();
        assertThat(included).containsExactly("/*api*/**");
        assertThat(paths.excludedPatterns()).containsExactly("/actuator/**");
        assertThatThrownBy(() -> included.add("/x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
