package by.darkimpulsepoint.lab4.security;

import by.darkimpulsepoint.lab4.config.JwtProperties;
import by.darkimpulsepoint.lab4.security.TokenException.Code;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Выпуск и проверка access-токенов.
 * <p>
 * Алгоритм зафиксирован на сервере (HS256) и никогда не берётся из заголовка токена:
 * так закрываются атаки {@code alg: none} и путаница HS256/RS256.
 */
public class JwtService {

    public static final String ALGORITHM = "HS256";
    public static final String TYPE_ACCESS = "access";
    private static final String HMAC = "HmacSHA256";

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final JsonMapper json = JsonMapper.builder().build();
    private final SecretKeySpec key;
    private final JwtProperties properties;
    private final Clock clock;

    public JwtService(JwtProperties properties, Clock clock) {
        this.key = new SecretKeySpec(SecretStrength.requireStrong(properties.secret()), HMAC);
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * В payload только то, что нужно для авторизации: id, имя, роли, тип и сроки.
     * Email, пароль и прочие персональные данные сюда не попадают — payload лишь закодирован, а не зашифрован.
     */
    public String issueAccessToken(long userId, String username, List<String> roles) {
        Instant now = clock.instant();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALGORITHM);
        header.put("typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", properties.issuer());
        payload.put("sub", Long.toString(userId));
        payload.put("name", username);
        payload.put("roles", roles);
        payload.put("type", TYPE_ACCESS);
        payload.put("iat", now.getEpochSecond());
        payload.put("exp", now.plus(properties.accessTtl()).getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());

        String signingInput = encode(header) + "." + encode(payload);
        return signingInput + "." + B64.encodeToString(hmac(signingInput));
    }

    public AccessTokenClaims verifyAccessToken(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenException(Code.TOKEN_MISSING, "Access token is missing");
        }
        // Ровно три непустые части: токен с пустой подписью (alg none) отбрасывается уже здесь.
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new TokenException(Code.TOKEN_MALFORMED, "Token must consist of header.payload.signature");
        }

        Map<String, Object> header = decode(parts[0]);
        // Сравниваем с жёстко заданным значением: none, None, RS256, HS512 и т.п. — отказ.
        if (!ALGORITHM.equals(header.get("alg"))) {
            throw new TokenException(Code.ALGORITHM_NOT_ALLOWED, "Only " + ALGORITHM + " is accepted");
        }

        byte[] expected = hmac(parts[0] + "." + parts[1]);
        byte[] actual;
        try {
            actual = B64D.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenException(Code.TOKEN_MALFORMED, "Signature is not base64url");
        }
        // Сравнение за постоянное время, чтобы подпись нельзя было подбирать по времени ответа.
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new TokenException(Code.INVALID_SIGNATURE, "Signature is invalid");
        }

        // Claims читаем только после проверки подписи.
        Map<String, Object> payload = decode(parts[1]);
        if (!properties.issuer().equals(payload.get("iss"))) {
            throw new TokenException(Code.INVALID_CLAIMS, "Unexpected issuer");
        }
        if (!TYPE_ACCESS.equals(payload.get("type"))) {
            throw new TokenException(Code.WRONG_TOKEN_TYPE, "Token type must be access");
        }
        if (!(payload.get("exp") instanceof Number exp) || !(payload.get("iat") instanceof Number iat)
                || !(payload.get("sub") instanceof String sub) || !(payload.get("name") instanceof String name)
                || !(payload.get("roles") instanceof List<?> rawRoles)) {
            throw new TokenException(Code.INVALID_CLAIMS, "Required claims are missing");
        }
        Instant expiresAt = Instant.ofEpochSecond(exp.longValue());
        if (!clock.instant().isBefore(expiresAt)) {
            throw new TokenException(Code.TOKEN_EXPIRED, "Access token has expired");
        }

        long userId;
        try {
            userId = Long.parseLong(sub);
        } catch (NumberFormatException e) {
            throw new TokenException(Code.INVALID_CLAIMS, "Subject is not a user id");
        }
        List<String> roles = rawRoles.stream().map(String::valueOf).toList();
        return new AccessTokenClaims(userId, name, roles, Instant.ofEpochSecond(iat.longValue()), expiresAt);
    }

    private String encode(Map<String, Object> value) {
        return B64.encodeToString(json.writeValueAsBytes(value));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decode(String part) {
        try {
            Object value = json.readValue(B64D.decode(part), Object.class);
            if (value instanceof Map<?, ?> map) {
                return (Map<String, Object>) map;
            }
        } catch (IllegalArgumentException | JacksonException e) {
            // ниже — общий ответ
        }
        throw new TokenException(Code.TOKEN_MALFORMED, "Token part is not a base64url JSON object");
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(key);
            return mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
