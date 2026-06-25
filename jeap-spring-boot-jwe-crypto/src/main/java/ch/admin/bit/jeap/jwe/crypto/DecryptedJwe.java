package ch.admin.bit.jeap.jwe.crypto;

/**
 * Result of decrypting an inbound JWE: the recovered plaintext and the declared content type
 * ({@code cty} protected-header value).
 *
 * <p>The request's content-encryption key is intentionally not exposed: the response is encrypted
 * with a separate CEK supplied by the client in the {@code JWE-Response-Key} header, not with the
 * request's CEK.
 *
 * @param plaintext   the decrypted payload bytes
 * @param contentType the {@code cty} from the JWE protected header (may be {@code null})
 */
@SuppressWarnings("java:S6218") // array equals not required here
public record DecryptedJwe(byte[] plaintext, String contentType) {
}
