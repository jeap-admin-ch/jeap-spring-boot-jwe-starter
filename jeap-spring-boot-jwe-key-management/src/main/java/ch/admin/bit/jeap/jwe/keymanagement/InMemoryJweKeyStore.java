package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * In-memory {@link JweKeyStore} backed by an immutable snapshot swapped atomically.
 *
 * <p>Reads are lock-free and always observe a fully consistent snapshot: the ordered key list and
 * the {@code kid} index are computed once in {@link Snapshot#of(Collection)} and published together
 * through a single {@link AtomicReference}. {@link #replaceKeys(Collection)} swaps the whole snapshot
 * in one volatile write, so a periodic refresh never exposes a half-updated key set.
 */
public class InMemoryJweKeyStore implements JweKeyStore {

    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(Snapshot.empty());

    /**
     * Atomically replaces the active key set. The given keys are ordered newest-version first; the
     * previous snapshot is discarded.
     */
    public void replaceKeys(Collection<RSAKey> keys) {
        snapshot.set(Snapshot.of(keys));
    }

    @Override
    public List<RSAKey> activeKeys() {
        return snapshot.get().orderedKeys();
    }

    @Override
    public Optional<RSAKey> currentEncryptionKey() {
        List<RSAKey> keys = snapshot.get().orderedKeys();
        return keys.isEmpty() ? Optional.empty() : Optional.of(keys.getFirst());
    }

    @Override
    public Optional<RSAKey> findByKeyId(String keyId) {
        return Optional.ofNullable(snapshot.get().byKeyId().get(keyId));
    }

    /**
     * Immutable, consistent view of the active keys: ordered list plus its {@code kid} index.
     */
    private record Snapshot(List<RSAKey> orderedKeys, Map<String, RSAKey> byKeyId) {

        private static final Snapshot EMPTY = new Snapshot(List.of(), Map.of());

        static Snapshot empty() {
            return EMPTY;
        }

        static Snapshot of(Collection<RSAKey> keys) {
            List<RSAKey> ordered = keys.stream()
                    .sorted(Comparator.comparingInt(Snapshot::versionOf).reversed())
                    .toList();
            Map<String, RSAKey> byKeyId = new LinkedHashMap<>();
            for (RSAKey key : ordered) {
                byKeyId.put(key.getKeyID(), key);
            }
            return new Snapshot(ordered, Map.copyOf(byKeyId));
        }

        /**
         * Extracts the integer version from the {@code kid} ({@code <transitKeyName>:<version>}).
         */
        private static int versionOf(RSAKey key) {
            String kid = key.getKeyID();
            if (kid == null || kid.lastIndexOf(':') < 0 || kid.endsWith(":")) {
                throw new IllegalArgumentException("Key ID does not contain a version suffix: " + kid);
            }
            int separator = kid.lastIndexOf(':');
            return Integer.parseInt(kid.substring(separator + 1));
        }
    }
}
