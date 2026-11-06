package by.darkimpulsepoint.lab4.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretStrengthTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void missingSecretIsRejected(String secret) {
        assertThatThrownBy(() -> SecretStrength.requireStrong(secret)).hasMessageContaining("not set");
    }

    @Test
    void shortSecretIsRejected() {
        assertThatThrownBy(() -> SecretStrength.requireStrong("Zq7vN3kT9pW2xR6mB8yL4cF1"))
                .hasMessageContaining("at least 32 bytes");
    }

    @Test
    void monotonousSecretIsRejected() {
        assertThatThrownBy(() -> SecretStrength.requireStrong("ab".repeat(32)))
                .hasMessageContaining("variety");
    }

    @ParameterizedTest
    @ValueSource(strings = {"test-lab4-secret-key-Zq7vN3kT9pW2xR6m", "Zq7vN3kT9pW2xR6mB8yL4cF1hJ5-CHANGEME"})
    void dictionarySecretIsRejected(String secret) {
        assertThatThrownBy(() -> SecretStrength.requireStrong(secret)).hasMessageContaining("dictionary");
    }

    @Test
    void randomSecretIsAccepted() {
        assertThat(SecretStrength.requireStrong("Zq7vN3kT9pW2xR6mB8yL4cF1hJ5sD0gUaEoIiYt")).hasSizeGreaterThanOrEqualTo(32);
    }
}
