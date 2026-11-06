package by.darkimpulsepoint.lab4.auth;

import by.darkimpulsepoint.lab4.api.ApiException;
import by.darkimpulsepoint.lab4.auth.AuthDtos.SigninRequest;
import by.darkimpulsepoint.lab4.auth.AuthDtos.SignupRequest;
import by.darkimpulsepoint.lab4.auth.AuthDtos.TokenPair;
import by.darkimpulsepoint.lab4.auth.AuthDtos.UserView;
import by.darkimpulsepoint.lab4.config.JwtProperties;
import by.darkimpulsepoint.lab4.security.JwtService;
import by.darkimpulsepoint.lab4.user.User;
import by.darkimpulsepoint.lab4.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    /** Хеш для выравнивания времени ответа, когда пользователя нет (не даём перебирать логины). */
    private String dummyHash;

    @Transactional
    public UserView signup(SignupRequest request) {
        if (users.existsByUsername(request.username())) {
            throw new ApiException(HttpStatus.CONFLICT, "USERNAME_TAKEN", "Username is already in use");
        }
        String email = request.email() == null || request.email().isBlank() ? null : request.email();
        if (email != null && users.existsByEmail(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "EMAIL_TAKEN", "Email is already in use");
        }
        User user = new User();
        user.setUsername(request.username());
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRoles(Set.of(User.ROLE_USER));
        user.setCreatedAt(clock.instant());
        users.save(user);
        log.info("User '{}' registered", user.getUsername());
        return toView(user);
    }

    /** Новый вход заменяет хеш предыдущего refresh-токена — действует только один. */
    @Transactional
    public TokenPair signin(SigninRequest request) {
        Optional<User> found = users.findByUsername(request.username());
        if (found.isEmpty()) {
            passwordEncoder.matches(request.password(), dummyHash());
            throw invalidCredentials();
        }
        User user = found.get();
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw invalidCredentials();
        }
        String refreshToken = RefreshTokens.generate();
        user.setRefreshTokenHash(RefreshTokens.sha256(refreshToken));
        user.setRefreshTokenExpiresAt(clock.instant().plus(jwtProperties.refreshTtl()));
        log.info("User '{}' signed in", user.getUsername());
        return pair(user, refreshToken);
    }

    /** Ротация: старый refresh-токен деактивируется сразу; повтор или истёкший токен — 401. */
    @Transactional(noRollbackFor = ApiException.class) // очистка истёкшего хеша должна сохраниться
    public TokenPair refresh(String refreshToken) {
        String oldHash = RefreshTokens.sha256(refreshToken);
        User user = users.findByRefreshTokenHash(oldHash).orElseThrow(AuthService::invalidRefresh);
        Instant now = clock.instant();
        if (!now.isBefore(user.getRefreshTokenExpiresAt())) {
            users.clearRefreshToken(user.getId());
            throw new ApiException(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_EXPIRED", "Refresh token has expired, sign in again");
        }
        String newToken = RefreshTokens.generate();
        int updated = users.rotateRefreshToken(user.getId(), oldHash, RefreshTokens.sha256(newToken),
                now.plus(jwtProperties.refreshTtl()), now);
        if (updated != 1) {
            throw invalidRefresh();
        }
        return pair(user, newToken);
    }

    @Transactional
    public void logout(long userId) {
        users.clearRefreshToken(userId);
    }

    @Transactional(readOnly = true)
    public UserView me(long userId) {
        return users.findById(userId).map(AuthService::toView)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "USER_NOT_FOUND", "User no longer exists"));
    }

    private TokenPair pair(User user, String refreshToken) {
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getUsername(), sortedRoles(user));
        return new TokenPair(accessToken, refreshToken, "Bearer",
                jwtProperties.accessTtl().toSeconds(), jwtProperties.refreshTtl().toSeconds());
    }

    private String dummyHash() {
        if (dummyHash == null) {
            dummyHash = passwordEncoder.encode("timing-equalizer-" + System.nanoTime());
        }
        return dummyHash;
    }

    private static List<String> sortedRoles(User user) {
        return user.getRoles().stream().sorted().toList();
    }

    private static UserView toView(User user) {
        return new UserView(user.getId(), user.getUsername(), user.getEmail(), sortedRoles(user));
    }

    private static ApiException invalidCredentials() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid username or password");
    }

    private static ApiException invalidRefresh() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or already used, sign in again");
    }
}
