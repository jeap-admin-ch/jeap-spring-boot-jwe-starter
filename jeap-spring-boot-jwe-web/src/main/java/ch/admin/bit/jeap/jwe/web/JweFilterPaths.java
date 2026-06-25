package ch.admin.bit.jeap.jwe.web;

import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;

/**
 * Decides which request paths the JWE filter applies to. The filter applies to a path when it matches
 * an <strong>include</strong> pattern and does <strong>not</strong> match an <strong>exclude</strong>
 * pattern — includes are evaluated first, excludes second (excludes win).
 *
 * <p>This keeps the filter off paths a Spring Boot app also serves directly (static resources, the SPA
 * shell, ...) in a Self-Contained-System setup: only the configured API paths are encrypted. The
 * built-in jEAP defaults (actuator, the JWKS and protocol-metadata endpoints, the jEAP SSE endpoint)
 * are always excluded, so they stay unencrypted even if the includes are broadened.
 *
 * <p>Matching uses {@link PathPattern} against the parsed, decoded and normalised
 * {@link PathContainer} Spring MVC routes on (not the raw request URI), so {@code %2e}/{@code %2f},
 * double slashes, matrix parameters or case tricks cannot change the decision.
 */
public final class JweFilterPaths {

    private final List<String> rawIncludes;
    private final List<String> rawExcludes;
    private final List<PathPattern> includes;
    private final List<PathPattern> excludes;

    public JweFilterPaths(List<String> includePatterns, List<String> excludePatterns) {
        this.rawIncludes = List.copyOf(includePatterns);
        this.rawExcludes = List.copyOf(excludePatterns);
        this.includes = parse(this.rawIncludes);
        this.excludes = parse(this.rawExcludes);
    }

    /**
     * @return {@code true} if the JWE filter applies to the given application-relative path
     * (matches an include and no exclude).
     */
    public boolean appliesTo(PathContainer pathWithinApplication) {
        return matchesAny(includes, pathWithinApplication) && !matchesAny(excludes, pathWithinApplication);
    }

    /**
     * Convenience overload that parses the given application-relative path string before matching.
     */
    public boolean appliesTo(String pathWithinApplication) {
        return appliesTo(PathContainer.parsePath(pathWithinApplication));
    }

    public List<String> includedPatterns() {
        return rawIncludes;
    }

    public List<String> excludedPatterns() {
        return rawExcludes;
    }

    private static List<PathPattern> parse(List<String> patterns) {
        return patterns.stream().map(PathPatternParser.defaultInstance::parse).toList();
    }

    private static boolean matchesAny(List<PathPattern> patterns, PathContainer path) {
        for (PathPattern pattern : patterns) {
            if (pattern.matches(path)) {
                return true;
            }
        }
        return false;
    }
}
