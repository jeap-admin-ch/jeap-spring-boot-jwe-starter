package ch.admin.bit.jeap.jwe.web;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JweServletFilterTest {

    private final JweServletFilter filter = new JweServletFilter(
            new JweFilterPaths(List.of("/**"), List.of("/actuator/**", "/.well-known/jwks.json")),
            TestJweKeyStores.none(),
            new JweFilterSettings(List.of("application/json"), "JWE-Response-Key"));

    @Test
    void excludedPathIsSkippedByFilter() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void nonExcludedPathIsFiltered() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void contextPathIsStrippedBeforeMatching() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/actuator/health");
        request.setContextPath("/app");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    // The include/exclude patterns are application-relative: under a context path, matching happens on
    // the path with the context stripped, so the default API include must not embed the context path.
    private final JweServletFilter apiFilter = new JweServletFilter(
            new JweFilterPaths(List.of("/*api*/**"), List.of()),
            TestJweKeyStores.none(),
            new JweFilterSettings(List.of("application/json"), "JWE-Response-Key"));

    @Test
    void includedApiPathUnderContextPathStaysFiltered() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/api/orders");
        request.setContextPath("/app");
        assertThat(apiFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void nonApiPathUnderContextPathStaysUnfiltered() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/public/info");
        request.setContextPath("/app");
        assertThat(apiFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void matrixParametersDoNotLetAProtectedPathEscapeEnforcement() {
        // A protected path decorated with matrix params must still be filtered (not treated as excluded).
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders;jsessionid=abc");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void matrixParametersDoNotBreakExclusionMatching() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health;v=1");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void exclusionMatchingIsCaseSensitiveSoUppercasePathStaysEnforced() {
        // Case-mismatched paths are NOT excluded -> they remain enforced (no bypass to skip encryption).
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/ACTUATOR/health");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void excludedPathPassesThroughUnchanged() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        // Excluded paths are passed through untouched (no decryption, no enforcement).
        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(chain.getResponse()).isSameAs(response);
    }
}
