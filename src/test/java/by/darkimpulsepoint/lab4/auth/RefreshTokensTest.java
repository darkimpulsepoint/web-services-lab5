package by.darkimpulsepoint.lab4.auth;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokensTest {

    @Test
    void tokensAreRandomAndUrlSafe() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            tokens.add(RefreshTokens.generate());
        }
        assertThat(tokens).hasSize(100).allMatch(t -> t.matches("[A-Za-z0-9_-]{43}"));
    }

    @Test
    void hashIsSha256HexAndNotTheTokenItself() {
        String token = RefreshTokens.generate();
        assertThat(RefreshTokens.sha256(token)).matches("[0-9a-f]{64}").isNotEqualTo(token)
                .isEqualTo(RefreshTokens.sha256(token));
        assertThat(RefreshTokens.sha256("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
