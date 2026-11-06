package by.darkimpulsepoint.lab4.security;

import by.darkimpulsepoint.lab4.config.JwtProperties;
import by.darkimpulsepoint.lab4.security.TokenException.Code;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "Zq7vN3kT9pW2xR6mB8yL4cF1hJ5sD0gUaEoIiYt";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final JwtService jwt = service(SECRET, Clock.systemUTC());

    private static JwtService service(String secret, Clock clock) {
        return new JwtService(new JwtProperties(secret, "lab4", Duration.ofMinutes(15), Duration.ofDays(7)), clock);
    }

    private static String b64(String json) {
        return B64.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String hs256(String signingInput, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return B64.encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String payloadOf(String token) {
        return new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    private static String validPayload(String type) {
        long now = Instant.now().getEpochSecond();
        return "{\"iss\":\"lab4\",\"sub\":\"1\",\"name\":\"alice\",\"roles\":[\"admin\"],\"type\":\"" + type
                + "\",\"iat\":" + now + ",\"exp\":" + (now + 600) + "}";
    }

    private static void assertRejected(JwtService service, String token, Code code) {
        assertThatThrownBy(() -> service.verifyAccessToken(token))
                .isInstanceOfSatisfying(TokenException.class, e -> assertThat(e.getCode()).isEqualTo(code));
    }

    @Test
    void issuedTokenIsAccepted() {
        AccessTokenClaims claims = jwt.verifyAccessToken(jwt.issueAccessToken(7, "alice", List.of("user")));
        assertThat(claims.userId()).isEqualTo(7);
        assertThat(claims.username()).isEqualTo("alice");
        assertThat(claims.roles()).containsExactly("user");
        assertThat(Duration.between(claims.issuedAt(), claims.expiresAt())).isEqualTo(Duration.ofMinutes(15));
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "None", "NONE", "nOnE"})
    void algNoneWithEmptySignatureIsRejected(String alg) {
        String token = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}") + "." + b64(validPayload("access")) + ".";
        assertRejected(jwt, token, Code.TOKEN_MALFORMED);
    }

    @Test
    void algNoneWithSomeSignatureIsRejected() {
        String token = b64("{\"alg\":\"none\"}") + "." + b64(validPayload("access")) + ".AAAA";
        assertRejected(jwt, token, Code.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void twoPartTokenIsRejected() {
        assertRejected(jwt, b64("{\"alg\":\"none\"}") + "." + b64(validPayload("access")), Code.TOKEN_MALFORMED);
    }

    @Test
    void rs256HeaderSignedWithHmacIsRejected() throws Exception {
        byte[] publicKeyAsSecret = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqh...-----END PUBLIC KEY-----"
                .getBytes(StandardCharsets.UTF_8);
        String rsInput = b64("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "." + b64(validPayload("access"));
        assertRejected(jwt, rsInput + "." + hs256(rsInput, publicKeyAsSecret), Code.ALGORITHM_NOT_ALLOWED);

        String hsInput = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64(validPayload("access"));
        assertRejected(jwt, hsInput + "." + hs256(hsInput, publicKeyAsSecret), Code.INVALID_SIGNATURE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"HS384", "HS512", "ES256", "PS256", "hs256", "HS256 "})
    void otherAlgorithmsAreRejected(String alg) throws Exception {
        String input = b64("{\"alg\":\"" + alg + "\"}") + "." + b64(validPayload("access"));
        assertRejected(jwt, input + "." + hs256(input, SECRET.getBytes(StandardCharsets.UTF_8)), Code.ALGORITHM_NOT_ALLOWED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "secret", "test-lab4-secret-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "my-super-secret-password-for-jwt-signing",
            "your-256-bit-secret-your-256-bit-secret!"})
    void weakSecretsAreRejectedAtStartup(String secret) {
        assertThatThrownBy(() -> service(secret, Clock.systemUTC())).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void tokenSignedWithAnotherSecretIsRejected() {
        String foreign = service("Pk4Xw9Lr2Tn7Vb1Mz5Qc8Hy3Jd6Gs0Fa", Clock.systemUTC())
                .issueAccessToken(1, "alice", List.of("admin"));
        assertRejected(jwt, foreign, Code.INVALID_SIGNATURE);
    }

    @Test
    void payloadContainsOnlyAuthorizationClaims() {
        String payload = payloadOf(jwt.issueAccessToken(1, "alice", List.of("user")));
        assertThat(payload).contains("\"sub\":\"1\"", "\"name\":\"alice\"", "\"roles\":[\"user\"]", "\"type\":\"access\"");
        assertThat(payload).doesNotContainIgnoringCase("password").doesNotContainIgnoringCase("email")
                .doesNotContainIgnoringCase("refresh");
    }

    @Test
    void tamperedPayloadIsRejected() {
        String[] parts = jwt.issueAccessToken(1, "alice", List.of("user")).split("\\.");
        String forged = parts[0] + "." + b64(payloadOf(String.join(".", parts)).replace("[\"user\"]", "[\"admin\"]")) + "." + parts[2];
        assertRejected(jwt, forged, Code.INVALID_SIGNATURE);
    }

    @Test
    void expiredTokenIsReportedSeparately() {
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofMinutes(16)), ZoneOffset.UTC);
        String token = service(SECRET, past).issueAccessToken(1, "alice", List.of("user"));
        assertRejected(jwt, token, Code.TOKEN_EXPIRED);
    }

    @Test
    void tokenOfAnotherTypeIsRejected() throws Exception {
        String input = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64(validPayload("refresh"));
        assertRejected(jwt, input + "." + hs256(input, SECRET.getBytes(StandardCharsets.UTF_8)), Code.WRONG_TOKEN_TYPE);
    }

    @Test
    void missingTokenIsRejected() {
        assertRejected(jwt, null, Code.TOKEN_MISSING);
        assertRejected(jwt, "garbage", Code.TOKEN_MALFORMED);
    }
}
