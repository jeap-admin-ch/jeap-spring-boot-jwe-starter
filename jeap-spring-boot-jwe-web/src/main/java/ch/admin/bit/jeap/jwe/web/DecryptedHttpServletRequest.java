package ch.admin.bit.jeap.jwe.web;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Wraps a request whose JWE body has been decrypted, presenting the plaintext bytes and the
 * {@code cty} content type so the {@code DispatcherServlet} and controllers see ordinary content
 * (e.g. {@code application/json}) and never know about the encryption.
 */
final class DecryptedHttpServletRequest extends HttpServletRequestWrapper {

    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String CONTENT_LENGTH_HEADER = "Content-Length";

    private final byte[] body;
    private final String contentType;

    DecryptedHttpServletRequest(HttpServletRequest request, byte[] body, String contentType) {
        super(request);
        this.body = body;
        this.contentType = contentType;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream source = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return source.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                throw new UnsupportedOperationException("Async reads are not supported for decrypted JWE requests");
            }

            @Override
            public int read() {
                return source.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return source.read(b, off, len);
            }

            @Override
            public int available() {
                return source.available();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }

    @Override
    public String getHeader(String name) {
        if (CONTENT_TYPE_HEADER.equalsIgnoreCase(name)) {
            return contentType;
        }
        if (CONTENT_LENGTH_HEADER.equalsIgnoreCase(name)) {
            return Integer.toString(body.length);
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (CONTENT_TYPE_HEADER.equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(contentType));
        }
        if (CONTENT_LENGTH_HEADER.equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(Integer.toString(body.length)));
        }
        return super.getHeaders(name);
    }
}
