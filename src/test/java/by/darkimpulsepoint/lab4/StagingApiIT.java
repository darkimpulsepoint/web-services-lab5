package by.darkimpulsepoint.lab4;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "IT_BASE_URL", matches = ".+")
class StagingApiIT {

    private static final String BASE_URL = System.getenv("IT_BASE_URL");
    private static final String MGMT_URL = System.getenv("IT_MGMT_URL");
    private static final String EXPECTED_VERSION = System.getenv("IT_EXPECTED_VERSION");

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final JsonMapper json = JsonMapper.builder().build();

    private record Response(int status, JsonNode body) {
    }

    private Response send(String method, String url, String body, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json");
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        JsonNode node = response.body().isBlank() ? null : json.readTree(response.body());
        return new Response(response.statusCode(), node);
    }

    private Response post(String path, String body, String token) throws Exception {
        return send("POST", BASE_URL + path, body, token);
    }

    private Response get(String path, String token) throws Exception {
        return send("GET", BASE_URL + path, null, token);
    }

    @Test
    void deployedVersionIsHealthy() throws Exception {
        if (MGMT_URL == null || MGMT_URL.isBlank()) {
            return;
        }
        assertThat(send("GET", MGMT_URL + "/actuator/health", null, null).body().get("status").asString()).isEqualTo("UP");
        if (EXPECTED_VERSION != null && !EXPECTED_VERSION.isBlank()) {
            JsonNode info = send("GET", MGMT_URL + "/actuator/info", null, null).body();
            assertThat(info.at("/app/version").asString()).isEqualTo(EXPECTED_VERSION);
        }
    }

    @Test
    void fullAuthFlowAgainstRealDatabase() throws Exception {
        assertThat(get("/api/test/all", null).status()).isEqualTo(200);

        String username = "it" + UUID.randomUUID().toString().substring(0, 8);
        Response signup = post("/api/auth/signup",
                "{\"username\":\"" + username + "\",\"email\":\"" + username + "@example.com\",\"password\":\"password123\"}", null);
        assertThat(signup.status()).isEqualTo(201);
        assertThat(signup.body().has("passwordHash")).isFalse();

        Response signin = post("/api/auth/signin", "{\"username\":\"" + username + "\",\"password\":\"password123\"}", null);
        assertThat(signin.status()).isEqualTo(200);
        String access = signin.body().get("accessToken").asString();
        String refresh = signin.body().get("refreshToken").asString();

        assertThat(get("/api/test/user", access).status()).isEqualTo(200);
        assertThat(get("/api/users/me", access).body().get("username").asString()).isEqualTo(username);
        assertThat(get("/api/test/admin", access).status()).isEqualTo(403);

        Response rotated = post("/api/auth/refresh", "{\"refreshToken\":\"" + refresh + "\"}", null);
        assertThat(rotated.status()).isEqualTo(200);
        assertThat(post("/api/auth/refresh", "{\"refreshToken\":\"" + refresh + "\"}", null).status()).isEqualTo(401);

        assertThat(post("/api/auth/logout", null, rotated.body().get("accessToken").asString()).status()).isEqualTo(200);
        String newRefresh = rotated.body().get("refreshToken").asString();
        assertThat(post("/api/auth/refresh", "{\"refreshToken\":\"" + newRefresh + "\"}", null).status()).isEqualTo(401);
    }

    @Test
    void unsignedTokenIsRejected() throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        long now = System.currentTimeMillis() / 1000;
        String forged = b64.encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(("{\"iss\":\"lab4\",\"sub\":\"1\",\"name\":\"admin\",\"roles\":[\"admin\"],\"type\":\"access\",\"iat\":"
                + now + ",\"exp\":" + (now + 600) + "}").getBytes(StandardCharsets.UTF_8)) + ".x";

        Response response = get("/api/test/admin", forged);
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.body().get("error").asString()).isEqualTo("ALGORITHM_NOT_ALLOWED");
    }
}
