package ch.admin.bit.jeap.jwe.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.Collections;
import java.util.Enumeration;

/**
 * Rewrites the {@code Accept} header seen by the {@code DispatcherServlet} when the filter will encrypt
 * the response. The client sends {@code Accept: application/jose} (so the filter enforces encryption),
 * but the controller produces ordinary content (e.g. {@code application/json}); without this rewrite
 * Spring MVC content negotiation would reject the request with 406 before the controller runs. The
 * filter then encrypts whatever the controller produced.
 */
final class AcceptOverridingHttpServletRequest extends HttpServletRequestWrapper {

    private static final String ACCEPT_HEADER = "Accept";

    private final String acceptValue;

    AcceptOverridingHttpServletRequest(HttpServletRequest request, String acceptValue) {
        super(request);
        this.acceptValue = acceptValue;
    }

    @Override
    public String getHeader(String name) {
        return ACCEPT_HEADER.equalsIgnoreCase(name) ? acceptValue : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (ACCEPT_HEADER.equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(acceptValue));
        }
        return super.getHeaders(name);
    }
}
