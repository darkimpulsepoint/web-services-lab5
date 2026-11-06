package by.darkimpulsepoint.lab4;

import by.darkimpulsepoint.lab4.user.User;
import by.darkimpulsepoint.lab4.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIT {

    private final JsonMapper json = JsonMapper.builder().build();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository users;

    private ResultActions postJson(String url, String body) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private String register() throws Exception {
        String username = "u" + UUID.randomUUID().toString().substring(0, 8);
        postJson("/api/auth/signup", "{\"username\":\"" + username + "\",\"email\":\"" + username
                + "@example.com\",\"password\":\"password123\"}")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.roles[0]").value("user"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
        return username;
    }

    private JsonNode signin(String username, String password) throws Exception {
        return body(postJson("/api/auth/signin", "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}")
                .andExpect(status().isOk()));
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return postJson("/api/auth/refresh", "{\"refreshToken\":\"" + refreshToken + "\"}");
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void fullTokenLifecycle() throws Exception {
        String username = register();
        JsonNode pair = signin(username, "password123");
        String access = pair.get("accessToken").asString();
        String refresh = pair.get("refreshToken").asString();

        User stored = users.findByUsername(username).orElseThrow();
        assertThat(stored.getPasswordHash()).startsWith("$2").isNotEqualTo("password123");
        assertThat(stored.getRefreshTokenHash()).isEqualTo(sha256(refresh)).isNotEqualTo(refresh);
        assertThat(stored.getRefreshTokenExpiresAt()).isAfter(Instant.now().plusSeconds(6 * 24 * 3600));

        mvc.perform(get("/api/test/user").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.refreshTokenHash").doesNotExist());
        mvc.perform(get("/api/test/admin").header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden());

        JsonNode rotated = body(refresh(refresh).andExpect(status().isOk()));
        String newRefresh = rotated.get("refreshToken").asString();
        assertThat(newRefresh).isNotEqualTo(refresh);
        refresh(refresh).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_REFRESH_TOKEN"));

        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + rotated.get("accessToken").asString()))
                .andExpect(status().isOk());
        assertThat(users.findByUsername(username).orElseThrow().getRefreshTokenHash()).isNull();
        refresh(newRefresh).andExpect(status().isUnauthorized());
    }

    @Test
    void newSigninReplacesPreviousRefreshToken() throws Exception {
        String username = register();
        String first = signin(username, "password123").get("refreshToken").asString();
        String second = signin(username, "password123").get("refreshToken").asString();
        refresh(first).andExpect(status().isUnauthorized());
        refresh(second).andExpect(status().isOk());
    }

    @Test
    void expiredRefreshTokenRequiresNewSignin() throws Exception {
        String username = register();
        String refresh = signin(username, "password123").get("refreshToken").asString();
        User user = users.findByUsername(username).orElseThrow();
        user.setRefreshTokenExpiresAt(Instant.now().minusSeconds(1));
        users.save(user);

        refresh(refresh).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("REFRESH_TOKEN_EXPIRED"));
        refresh(refresh).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_REFRESH_TOKEN"));
    }

    @Test
    void protectedRoutesRequireValidAccessToken() throws Exception {
        mvc.perform(get("/api/test/all")).andExpect(status().isOk());
        mvc.perform(get("/api/test/user")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("TOKEN_MISSING"));
        mvc.perform(get("/api/test/user").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized());

        String refresh = signin(register(), "password123").get("refreshToken").asString();
        mvc.perform(get("/api/test/user").header("Authorization", "Bearer " + refresh))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("TOKEN_MALFORMED"));
    }

    @Test
    void testEndpointReturnsPlainText() throws Exception {
        mvc.perform(get("/test")).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string("test ok"));
    }

    @Test
    void wrongCredentialsAreIndistinguishable() throws Exception {
        String username = register();
        postJson("/api/auth/signin", "{\"username\":\"" + username + "\",\"password\":\"wrong-password\"}")
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
        postJson("/api/auth/signin", "{\"username\":\"nobody-here\",\"password\":\"wrong-password\"}")
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
    }

    @Test
    void adminFromEnvironmentCanOpenAdminRoute() throws Exception {
        String access = signin("admin", "admin-password-123").get("accessToken").asString();
        mvc.perform(get("/api/test/admin").header("x-access-token", access)).andExpect(status().isOk());
    }

    @Test
    void signupValidatesInputAndRejectsDuplicates() throws Exception {
        postJson("/api/auth/signup", "{\"username\":\"ab\",\"password\":\"short\"}").andExpect(status().isBadRequest());
        String username = register();
        postJson("/api/auth/signup", "{\"username\":\"" + username + "\",\"password\":\"password123\"}")
                .andExpect(status().isConflict());
    }
}
