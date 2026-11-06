package by.darkimpulsepoint.lab4.security;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

final class SecretStrength {

    static final int MIN_BYTES = 16;
    private static final int MIN_DISTINCT_CHARS = 16;
    private static final Set<String> KNOWN_WEAK_FRAGMENTS = Set.of(
            "secret", "password", "changeme", "qwerty", "123456", "test-lab4", "your-256-bit", "example");

    private SecretStrength() {
    }

    static byte[] requireStrong(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET is not set");
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_BYTES) {
            throw new IllegalStateException("JWT_SECRET must be at least " + MIN_BYTES + " bytes (256 bits)");
        }
        if (secret.chars().distinct().count() < MIN_DISTINCT_CHARS) {
            throw new IllegalStateException("JWT_SECRET has too little variety, use a random value (e.g. openssl rand -base64 48)");
        }
        String lower = secret.toLowerCase(Locale.ROOT);
        for (String fragment : KNOWN_WEAK_FRAGMENTS) {
            if (lower.contains(fragment)) {
                throw new IllegalStateException("JWT_SECRET looks like a dictionary/default value, use a random value");
            }
        }
        return bytes;
    }
}
